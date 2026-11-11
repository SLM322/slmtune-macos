import AppKit
import SwiftUI
import UniformTypeIdentifiers
@testable import SLMShared

struct ServersView: View {
    @EnvironmentObject var state: AppState
    @State private var selection = Set<String>()
    @State private var editing: Server?
    @State private var sharing: (title: String, link: String)?
    @State private var newGroup = false
    @State private var torAdd = false
    @State private var filter = ""

    private var shown: [Server] {
        filter.isEmpty ? state.settings.servers
            : state.settings.servers.filter { $0.title.localizedCaseInsensitiveContains(filter) || $0.server.localizedCaseInsensitiveContains(filter) }
    }

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                Text(L("Серверы")).font(.system(size: 24, weight: .semibold))
                Spacer()
                TextField(L("Поиск"), text: $filter).frame(width: 180)
                Menu(L("Добавить")) {
                    Button(L("Из буфера (⇧⌘V)")) { state.pasteFromClipboard() }
                    Button(L("QR-код с экрана")) { state.importFromScreen() }
                    Button(L("QR-код из картинки…")) { pickImage() }
                    Button(L("Файл .conf / .txt…")) { pickFile() }
                    Divider()
                    Button(L("Группа серверов…")) { newGroup = true }
                    Divider()
                    Button("Cloudflare WARP") { Task { await state.addWarp(obfuscate: false) } }
                    Button(L("Cloudflare WARP с маскировкой (AmneziaWG)")) { Task { await state.addWarp(obfuscate: true) } }
                    Button("Tor…") { torAdd = true }
                }
                .frame(width: 120)
                Button(L("Пинг")) { Task { await state.pingAll() } }
            }
            .padding(.horizontal, 22).padding(.top, 22).padding(.bottom, 10)

            Table(shown, selection: $selection) {
                TableColumn("") { s in
                    Image(systemName: s.id == state.settings.activeId ? "largecircle.fill.circle" : "circle")
                        .foregroundStyle(s.id == state.settings.activeId ? Slm.accent2 : Slm.text3)
                }.width(22)
                TableColumn(L("Название")) { s in
                    VStack(alignment: .leading, spacing: 2) {
                        Text(s.title)
                        if let via = state.settings.server(s.viaId) { Text(L("через «%@»", via.title)).font(.caption).foregroundStyle(Slm.accent2) }
                    }
                }
                TableColumn(L("Протокол")) { s in Text(ShareLinks.describe(s)).foregroundStyle(Slm.text2) }.width(min: 120, ideal: 170)
                TableColumn(L("Адрес")) { s in Text(s.kind == "group" ? L("%d серверов", s.members.count) : "\(s.server):\(s.port)").foregroundStyle(Slm.text2).lineLimit(1) }
                TableColumn(L("Пинг")) { s in Text(pingText(s)).monospacedDigit().foregroundStyle(pingColor(s)) }.width(70)
            }
            .contextMenu(forSelectionType: String.self) { ids in
                if let id = ids.first, let s = state.settings.server(id) {
                    Button(L("Выбрать")) { state.select(s) }
                    Button(L("Изменить…")) { editing = s }
                    if let link = ShareLinks.export(s) {
                        Button(L("QR-код и ссылка…")) { sharing = (s.title, link) }
                        Button(L("Скопировать ссылку")) { copyToClipboard(link) }
                    }
                    Menu(L("Через сервер (каскад)")) {
                        Button(L("Напрямую")) { var x = s; x.viaId = ""; state.update(x) }
                        ForEach(state.settings.servers.filter { $0.id != s.id }) { r in
                            Button((s.viaId == r.id ? "✓ " : "") + r.title) { var x = s; x.viaId = r.id; state.update(x) }
                        }
                    }
                }
                Divider()
                Button(L("Удалить"), role: .destructive) { state.remove(ids) }
            } primaryAction: { ids in
                if let id = ids.first, let s = state.settings.server(id) { state.select(s) }
            }
            .onDeleteCommand { state.remove(selection) }
        }
        .background(Slm.ink)
        .sheet(item: $editing) { s in ServerEditSheet(server: s) }
        .sheet(isPresented: $newGroup) { GroupSheet() }
        .sheet(isPresented: $torAdd) { TorAddSheet() }
        .sheet(item: Binding(get: { sharing.map { IdentifiedString(value: $0.title + "\n" + $0.link) } }, set: { if $0 == nil { sharing = nil } })) { _ in
            if let s = sharing { ShareSheet(title: s.title, link: s.link) }
        }
        .onDrop(of: [.fileURL, .plainText], isTargeted: nil) { providers in
            for p in providers {
                _ = p.loadObject(ofClass: URL.self) { url, _ in
                    if let url, let t = try? String(contentsOf: url, encoding: .utf8) { Task { @MainActor in state.importText(t) } }
                }
                _ = p.loadObject(ofClass: String.self) { t, _ in if let t { Task { @MainActor in state.importText(t) } } }
            }
            return true
        }
    }

    private func pingText(_ s: Server) -> String {
        switch s.pingMs { case -1: return "—"; case -2: return L("нет"); case -3: return "UDP"; default: return "\(s.pingMs) " + L("мс") }
    }

    private func pingColor(_ s: Server) -> Color {
        s.pingMs == -2 ? Slm.err : s.pingMs < 0 ? Slm.text3 : s.pingMs < 150 ? Slm.ok : s.pingMs < 400 ? Slm.warn : Slm.err
    }

    private func pickFile() {
        let p = NSOpenPanel()
        p.allowedContentTypes = [.plainText, UTType(filenameExtension: "conf") ?? .data, UTType(filenameExtension: "toml") ?? .data]
        p.allowsMultipleSelection = true
        guard p.runModal() == .OK else { return }
        for u in p.urls {
            guard let t = try? String(contentsOf: u, encoding: .utf8) else { continue }
            if var wg = ShareLinks.parseWireGuardConf(t, name: u.deletingPathExtension().lastPathComponent) {
                wg = MoreLinks.classifyWireGuard(wg)
                state.add([wg])
            } else { state.importText(t) }
        }
    }

    private func pickImage() {
        let p = NSOpenPanel()
        p.allowedContentTypes = [.image]
        guard p.runModal() == .OK, let u = p.url else { return }
        let codes = ScreenQR.decode(file: u)
        if codes.isEmpty { state.show(L("На картинке нет QR-кода.")) } else { state.importText(codes.joined(separator: "\n")) }
    }
}

/// Name, address and the link's parameters.
struct ServerEditSheet: View {
    @EnvironmentObject var state: AppState
    @Environment(\.dismiss) private var dismiss
    @State var server: Server
    @State private var link = ""

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text(L("Сервер")).font(.headline)
            Form {
                TextField(L("Название"), text: $server.name)
                if server.kind != "group" && server.kind != "tor" {
                    TextField(L("Адрес"), text: $server.server)
                    TextField(L("Порт"), value: $server.port, format: .number.grouping(.never))
                }
                LabeledContent(L("Протокол"), value: ShareLinks.describe(server))
                if server.kind == "group" {
                    Picker(L("Как выбирать"), selection: Binding(get: { server.param("mode", "auto") }, set: { server.params["mode"] = $0 })) {
                        Text(L("Самый быстрый")).tag("auto")
                        Text(L("Резерв по порядку")).tag("fallback")
                    }
                }
            }
            Text(L("Или вставьте новую ссылку — сервер заменится, название останется:")).font(.caption).foregroundStyle(Slm.text2)
            TextField("vless://…", text: $link)
            HStack {
                Spacer()
                Button(L("Отмена")) { dismiss() }
                Button(L("Сохранить")) {
                    if !link.isEmpty, var n = try? ShareLinks.parse(link) {
                        n.id = server.id; n.name = server.name; n.viaId = server.viaId
                        server = n
                    }
                    state.update(server)
                    dismiss()
                }.keyboardShortcut(.defaultAction)
            }
        }
        .padding(22).frame(width: 520)
    }
}

/// A group: the fastest of several servers (urltest), or the first working one.
struct GroupSheet: View {
    @EnvironmentObject var state: AppState
    @Environment(\.dismiss) private var dismiss
    @State private var name = L("Авто: лучший сервер")
    @State private var mode = "auto"
    @State private var picked: [String] = []

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text(L("Группа серверов")).font(.headline)
            TextField(L("Название"), text: $name)
            Picker(L("Как выбирать"), selection: $mode) {
                Text(L("Самый быстрый — проверяет задержку и переключается сам")).tag("auto")
                Text(L("Резерв — первый работающий по порядку")).tag("fallback")
            }
            Text(L("Серверы (в порядке отметки):")).font(.caption).foregroundStyle(Slm.text2)
            List(state.settings.servers.filter { $0.kind != "group" }) { s in
                Toggle(isOn: Binding(get: { picked.contains(s.id) }, set: { on in
                    if on { picked.append(s.id) } else { picked.removeAll { $0 == s.id } }
                })) { Text("\(s.title) · \(ShareLinks.describe(s))") }
            }
            .frame(height: 260)
            HStack {
                Spacer()
                Button(L("Отмена")) { dismiss() }
                Button(L("Добавить")) {
                    state.add([Server(name: name, kind: "group", server: "group", port: 1, params: ["mode": mode], members: picked)])
                    dismiss()
                }
                .disabled(picked.count < 2)
                .keyboardShortcut(.defaultAction)
            }
        }
        .padding(22).frame(width: 520)
    }
}

struct TorAddSheet: View {
    @EnvironmentObject var state: AppState
    @Environment(\.dismiss) private var dismiss
    @State private var transport = "snowflake"
    @State private var bridges = ""

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Tor").font(.headline)
            Picker(L("Мосты"), selection: $transport) {
                Text(L("Snowflake — через WebRTC-волонтёров, работает почти везде")).tag("snowflake")
                Text(L("obfs4 — случайный шум, встроенные мосты")).tag("obfs4")
                Text(L("meek — через CDN Microsoft Azure, медленно, но надёжно")).tag("meek")
                Text(L("WebTunnel — выглядит как обычный HTTPS-сайт (мосты из @GetBridgesBot)")).tag("webtunnel")
                Text(L("Свои мосты (с bridges.torproject.org или из @GetBridgesBot)")).tag("custom")
                Text(L("Без мостов — если Tor у провайдера не заблокирован")).tag("none")
            }
            .pickerStyle(.radioGroup)
            if transport == "webtunnel" || transport == "custom" {
                TextEditor(text: $bridges).font(.system(.caption, design: .monospaced)).frame(height: 120)
            }
            Text(L("Tor передаёт только TCP: игры и звонки по UDP через него не пойдут. Первый запуск — до двух минут."))
                .font(.caption).foregroundStyle(Slm.text2)
            HStack {
                Spacer()
                Button(L("Отмена")) { dismiss() }
                Button(L("Добавить")) {
                    state.add([MoreLinks.torProfile(transport: transport, bridges: bridges)])
                    dismiss()
                }.keyboardShortcut(.defaultAction)
            }
        }
        .padding(22).frame(width: 560)
    }
}
