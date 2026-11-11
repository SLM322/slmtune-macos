import SwiftUI
@testable import SLMShared

/// «Мои серверы»: your own VPS set up over SSH — protocols, users with limits, links for the app and others.
struct MyServersView: View {
    @EnvironmentObject var state: AppState
    @State private var adding = false

    var body: some View {
        SlmList {
            Section {
                ForEach(state.settings.myServers) { s in
                    NavigationLink { MyServerView(session: ServerSession(s)) } label: {
                        VStack(alignment: .leading) {
                            Text(s.title)
                            Text("\(s.user)@\(s.host):\(s.port)").font(.caption).foregroundStyle(Slm.text2)
                        }
                    }
                }
                .onDelete { state.settings.myServers.remove(atOffsets: $0) }
                Button { adding = true } label: { Label("Добавить сервер", systemImage: "plus") }
            } footer: {
                Text("Нужен VPS с Ubuntu или Debian и доступ root по SSH (данные из письма хостинга). Программа сама поставит sing-box, откроет порты и выдаст ссылки. Пароль не сохраняется: после первого входа на сервер кладётся ключ приложения.")
            }
            .slmRow()
        }
        .navigationTitle("Мои серверы")
        
        .sheet(isPresented: $adding) { AddMyServer() }
    }
}

private struct AddMyServer: View {
    @EnvironmentObject var state: AppState
    @Environment(\.dismiss) private var dismiss
    @State private var s = MyServer()
    @State private var port = "22"

    var body: some View {
        NavigationStack {
            SlmList {
                Section {
                    TextField("Название (необязательно)", text: $s.name)
                    TextField("Адрес (IP или домен)", text: $s.host).autocorrectionDisabled()
                    TextField("Порт SSH", text: $port)
                    TextField("Пользователь", text: $s.user).autocorrectionDisabled()
                }
                .slmRow()
            }
            .navigationTitle("Новый сервер")
            
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("Отмена") { dismiss() } }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Добавить") {
                        s.host = s.host.trimmingCharacters(in: .whitespaces)
                        s.port = Int(port) ?? 22
                        state.settings.myServers.append(s)
                        dismiss()
                    }
                    .disabled(s.host.trimmingCharacters(in: .whitespaces).isEmpty || s.user.isEmpty)
                }
            }
        }
    }
}

struct MyServerView: View {
    @EnvironmentObject var state: AppState
    @StateObject var session: ServerSession
    @State private var pendingKey: String?
    @State private var error: String?
    @State private var plan: [String: String] = [:] // protocol → port text; absent = off
    @State private var domain = ""
    @State private var sni = "www.microsoft.com"
    @State private var bbr = true
    @State private var newUser = ""
    @State private var share: IdentifiedString?
    @State private var showLog = false

    var body: some View {
        SlmList {
            connectSection
            if let info = session.info, let cfg = session.cfg {
                Section("Сервер") {
                    LabeledContent("Система", value: "\(info.os) · \(info.arch)")
                    LabeledContent("sing-box", value: info.singBox.isEmpty ? L("не установлен") : "\(info.singBox) · \(info.singBoxActive)")
                    LabeledContent(L("Нагрузка"), value: String(format: "%.2f / %d CPU", info.load, info.cpus))
                    LabeledContent(L("Память"), value: "\(info.memUsed) / \(info.memTotal) " + L("МБ"))
                }
                .slmRow()
                protocolsSection(cfg)
                usersSection(cfg)
                toolsSection
            }
            if let error { Text(error).foregroundStyle(Slm.err).slmRow() }
        }
        .navigationTitle(session.server.title)
        
        .toolbar {
            ToolbarItem(placement: .primaryAction) {
                if session.busy { ProgressView() } else { Button { showLog = true } label: { Image(systemName: "text.alignleft") } }
            }
        }
        .sheet(isPresented: $showLog) { SessionLog(session: session) }
        .sheet(item: $share) { ShareServerView(link: $0.value) }
        .alert("Ключ сервера", isPresented: Binding(get: { pendingKey != nil }, set: { if !$0 { pendingKey = nil } })) {
            Button("Доверять") {
                if let k = pendingKey { session.server.hostKey = k; save(); Task { await connect() } }
                pendingKey = nil
            }
            Button("Отмена", role: .cancel) { pendingKey = nil }
        } message: {
            Text(L("Сверьте отпечаток с панелью хостинга (или выполните на сервере ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub):\n\n%@", SSH.fingerprint(pendingKey ?? "")))
        }
        .onChange(of: session.version) { _ in loadPlan() }
    }

    // MARK: connect

    @ViewBuilder private var connectSection: some View {
        Section {
            if !session.server.keyInstalled {
                SecureField("Пароль SSH", text: $session.password)
            }
            Button {
                Task { await connect() }
            } label: {
                Label(session.info == nil ? "Подключиться" : "Обновить", systemImage: "bolt.horizontal.circle")
            }
            .disabled(session.busy)
        } footer: {
            if session.server.keyInstalled { Text("Вход по ключу приложения — пароль не нужен.") }
        }
        .slmRow()
    }

    private func save() {
        if let i = state.settings.myServers.firstIndex(where: { $0.id == session.server.id }) { state.settings.myServers[i] = session.server }
    }

    private func connect() async {
        error = nil
        do {
            if session.server.hostKey.isEmpty {
                pendingKey = try await SSH.scan(host: session.server.host, port: session.server.port)
                return
            }
            try await session.probe()
            if !session.server.keyInstalled, !session.password.isEmpty, try await session.installKey() {
                session.server.keyInstalled = true
                save()
            }
        } catch {
            self.error = error.localizedDescription
        }
    }

    private func loadPlan() {
        guard let c = session.cfg else { return }
        var p: [String: String] = [:]
        for (k, _) in ServerSession.protocols where c.has(k) { p[k] = "\(c.port(k))" }
        if p.isEmpty { p["vless"] = "443"; p["hy2"] = "443" } // a sensible start: Reality over TCP, Hysteria2 over UDP
        plan = p
        domain = c.domain(session.server.host)
        sni = c.realitySni
    }

    // MARK: protocols

    private func protocolsSection(_ c: MyServerConfig) -> some View {
        Section {
            ForEach(ServerSession.protocols, id: \.key) { p in
                HStack {
                    Toggle(isOn: Binding(get: { plan[p.key] != nil },
                                         set: { plan[p.key] = $0 ? "\(c.port(p.key))" : nil })) {
                        Text(LocalizedStringKey(p.title))
                    }
                    if plan[p.key] != nil {
                        TextField("порт", text: Binding(get: { plan[p.key] ?? "" }, set: { plan[p.key] = $0 }))
                            .multilineTextAlignment(.trailing).frame(width: 64)
                    }
                }
            }
            if plan.keys.contains(where: { ServerSession.withDomain.contains($0) }) {
                LabeledContent("Домен") {
                    TextField("1-2-3-4.sslip.io", text: $domain).multilineTextAlignment(.trailing)
                        .autocorrectionDisabled()
                }
            }
            if plan["vless"] != nil || plan["shadowtls"] != nil {
                LabeledContent("Сайт для маскировки") {
                    TextField("www.microsoft.com", text: $sni).multilineTextAlignment(.trailing)
                        .autocorrectionDisabled()
                }
            }
            Toggle("Ускорение BBR", isOn: $bbr)
            Button("Применить на сервере") { Task { await apply() } }.disabled(session.busy)
        } header: {
            Text("Протоколы")
        } footer: {
            Text("Протоколы с доменом получают сертификат Let's Encrypt (бесплатный домен вида 1-2-3-4.sslip.io подходит). Несколько протоколов на одном порту нельзя, кроме TCP и UDP.")
        }
        .slmRow()
    }

    private func apply() async {
        var ports: [String: Int] = [:]
        for (k, v) in plan { ports[k] = Int(v.trimmingCharacters(in: .whitespaces)) ?? -1 }
        let p = ServerSession.Plan(ports: ports, domain: domain.trimmingCharacters(in: .whitespaces).lowercased(),
                                   sni: sni.trimmingCharacters(in: .whitespaces).lowercased(), bbr: bbr)
        if let problem = session.check(p) { error = problem; return }
        error = nil
        do { try await session.apply(p) } catch { self.error = error.localizedDescription }
    }

    // MARK: users

    private func usersSection(_ c: MyServerConfig) -> some View {
        let today = ISO8601DateFormatter.string(from: Date(), timeZone: TimeZone(identifier: "UTC")!, formatOptions: [.withFullDate])
        return Section {
            ForEach(c.users) { u in
                let usage = c.usage(u)
                VStack(alignment: .leading, spacing: 6) {
                    HStack {
                        Text(u.name).font(.headline)
                        Spacer()
                        Text(LocalizedStringKey(stateTitle(c.state(u, today: today)))).font(.caption)
                            .foregroundStyle(c.state(u, today: today) == "on" ? Slm.ok : Slm.warn)
                    }
                    Text("↑ \(human(UInt64(usage.up)))  ↓ \(human(UInt64(usage.down)))" + (u.limit > 0 ? " / \(human(UInt64(u.limit)))" : "")
                         + (u.expires.isEmpty ? "" : " · " + L("до %@", u.expires)))
                        .font(.caption).foregroundStyle(Slm.text2)
                    HStack {
                        Button("В приложение") {
                            let list = c.profiles(host: session.server.host, user: u, label: session.server.title)
                            state.add(list)
                            state.show(L("Добавлено серверов: %d", list.count))
                        }
                        Menu("Ссылки") {
                            ForEach(c.links(host: session.server.host, user: u, label: session.server.title), id: \.link) { l in
                                Button(l.title) { share = IdentifiedString(value: l.link) }
                            }
                            if let tg = c.telegramLink(host: session.server.host, user: u) {
                                Button("Прокси для Telegram") { share = IdentifiedString(value: tg) }
                            }
                        }
                        Spacer()
                        Menu {
                            Button(u.off ? "Включить" : "Выключить") { edit(c, u) { $0.off.toggle() }; Task { try? await session.applyUsers() } }
                            Menu("Лимит трафика") {
                                ForEach([0, 10, 50, 100, 500], id: \.self) { gb in
                                    Button(gb == 0 ? L("Без лимита") : "\(gb) " + L("ГБ")) {
                                        edit(c, u) { $0.limit = Int64(gb) << 30 }; Task { try? await session.applyLimits() }
                                    }
                                }
                            }
                            Menu("Срок") {
                                ForEach([0, 7, 30, 90, 365], id: \.self) { days in
                                    Button(days == 0 ? L("Без срока") : L("%d дн.", days)) {
                                        let d = days == 0 ? "" : ISO8601DateFormatter.string(from: Date().addingTimeInterval(Double(days) * 86_400),
                                                                                            timeZone: TimeZone(identifier: "UTC")!, formatOptions: [.withFullDate])
                                        edit(c, u) { $0.expires = d }; Task { try? await session.applyLimits() }
                                    }
                                }
                            }
                            Button("Обнулить трафик") { Task { try? await session.resetUsage(u) } }
                            Button("Удалить", role: .destructive) {
                                c.users.removeAll { $0.id == u.id }; session.changed(); Task { try? await session.applyUsers() }
                            }
                        } label: { Image(systemName: "ellipsis.circle") }
                    }
                    .buttonStyle(.borderless)
                    .font(.footnote)
                }
            }
            HStack {
                TextField("Имя нового пользователя", text: $newUser).autocorrectionDisabled()
                Button {
                    do {
                        try c.addUser(newUser.trimmingCharacters(in: .whitespaces))
                        newUser = ""
                        session.changed()
                        Task { try? await session.applyUsers() }
                    } catch { self.error = error.localizedDescription }
                } label: { Image(systemName: "plus.circle.fill") }
                .disabled(newUser.trimmingCharacters(in: .whitespaces).isEmpty || session.busy || !c.anyProtocol)
            }
        } header: {
            Text("Пользователи")
        } footer: {
            Text("У каждого свои пароли и счётчик трафика. Выключенный или превысивший лимит пользователь не подключится.")
        }
        .slmRow()
    }

    private func edit(_ c: MyServerConfig, _ u: MyUser, _ f: (inout MyUser) -> Void) {
        guard let i = c.users.firstIndex(where: { $0.id == u.id }) else { return }
        f(&c.users[i])
        session.changed()
    }

    private func stateTitle(_ s: String) -> String {
        switch s {
        case "off": return "выключен"
        case "expired": return "срок истёк"
        case "limit": return "лимит исчерпан"
        default: return "активен"
        }
    }

    // MARK: tools

    private var toolsSection: some View {
        Section("Инструменты") {
            tool("Перезапустить sing-box", ServerScripts.restart)
            tool("Обновить sing-box", ServerScripts.updateSingBox)
            tool("Защитить сервер (fail2ban, SSH)", ServerScripts.harden)
            tool("Подкачка и точное время", ServerScripts.swapAndTime)
            tool("Автообновления системы", ServerScripts.autoUpdates)
            tool("Проверка сети сервера", ServerScripts.netCheck)
            tool("Журнал sing-box", ServerScripts.logs)
            tool("Перезагрузить сервер", ServerScripts.reboot)
        }
        .slmRow()
    }

    private func tool(_ title: String, _ script: String) -> some View {
        Button(LocalizedStringKey(title)) {
            Task {
                do { _ = try await session.run(script, L(title)); showLog = true } catch { self.error = error.localizedDescription }
            }
        }
        .disabled(session.busy)
    }
}

private struct SessionLog: View {
    @ObservedObject var session: ServerSession
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        NavigationStack {
            ScrollViewReader { proxy in
                ScrollView {
                    LazyVStack(alignment: .leading, spacing: 2) {
                        ForEach(Array(session.log.enumerated()), id: \.offset) { i, l in
                            Text(l).font(.system(size: 11, design: .monospaced)).foregroundStyle(l.hasPrefix("—") ? Slm.accent2 : Slm.text2).id(i)
                        }
                    }
                    .padding()
                    .textSelection(.enabled)
                }
                .onChange(of: session.log.count) { n in proxy.scrollTo(n - 1, anchor: .bottom) }
            }
            .background(Slm.ink)
            .navigationTitle("Журнал сервера")
            
            .toolbar { ToolbarItem(placement: .cancellationAction) { Button("Закрыть") { dismiss() } } }
        }
    }
}
