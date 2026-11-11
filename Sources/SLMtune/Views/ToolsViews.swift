import AppKit
import SwiftUI
@testable import SLMShared

// MARK: Соединения

struct ConnectionsView: View {
    @EnvironmentObject var state: AppState
    @EnvironmentObject var monitor: ClashMonitor
    @State private var filter = ""

    private var shown: [ClashMonitor.Conn] {
        filter.isEmpty ? monitor.connections
            : monitor.connections.filter { $0.host.localizedCaseInsensitiveContains(filter) || $0.process.localizedCaseInsensitiveContains(filter) }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack {
                Text(L("Соединения")).font(.system(size: 24, weight: .semibold))
                Spacer()
                TextField(L("Поиск"), text: $filter).frame(width: 200)
                Button(L("Закрыть все")) { Task { await monitor.closeAll() } }.disabled(state.status != .on)
            }
            .padding(22)
            if state.status != .on {
                Text(L("VPN выключен — соединений нет.")).foregroundStyle(Slm.text2).padding(.horizontal, 22)
                Spacer()
            } else {
                Table(shown) {
                    TableColumn(L("Программа")) { c in Text(c.process.isEmpty ? "—" : c.process).lineLimit(1) }.width(min: 100, ideal: 140)
                    TableColumn(L("Адрес")) { c in Text(c.host).lineLimit(1) }
                    TableColumn(L("Маршрут")) { c in Text(c.viaVpn ? "VPN" : c.chain == "zapret" ? "Zapret" : L("напрямую")).foregroundStyle(c.viaVpn ? Slm.accent2 : Slm.text2) }.width(90)
                    TableColumn(L("Сеть")) { c in Text(c.network.uppercased()).foregroundStyle(Slm.text3) }.width(50)
                    TableColumn(L("Трафик")) { c in Text("↓ \(human(c.down))  ↑ \(human(c.up))").monospacedDigit() }.width(150)
                }
                .contextMenu(forSelectionType: String.self) { ids in
                    Button(L("Закрыть соединение")) { for id in ids { Task { await monitor.close(id) } } }
                    if let c = monitor.connections.first(where: { ids.contains($0.id) }), !c.process.isEmpty {
                        Divider()
                        Button(L("«%@» — всегда через VPN", c.process)) { state.settings.appRules.append(AppRule(process: c.process, action: "vpn")) }
                        Button(L("«%@» — всегда напрямую", c.process)) { state.settings.appRules.append(AppRule(process: c.process, action: "direct")) }
                        Button(L("«%@» — блокировать", c.process)) { state.settings.appRules.append(AppRule(process: c.process, action: "block")) }
                    }
                }
            }
        }
        .background(Slm.ink)
    }
}

// MARK: Трафик за месяц

struct TrafficView: View {
    @EnvironmentObject var monitor: ClashMonitor
    @State private var month = MonthlyUsage.key(Date())

    struct Row: Identifiable { let id: String; let vpn: Int64; let direct: Int64; var total: Int64 { vpn + direct } }

    private var rows: [Row] {
        let data = month == MonthlyUsage.key(Date()) ? monitor.usage.current : MonthlyUsage.load(month)
        return data.map { Row(id: $0.key, vpn: $0.value.vpnDown + $0.value.vpnUp, direct: $0.value.directDown + $0.value.directUp) }
            .sorted { $0.total > $1.total }
    }

    var body: some View {
        Page(title: L("Трафик за месяц"), subtitle: L("Сколько каждая программа передала через VPN и напрямую. Хранится только на этом Mac. Программы различаются в режиме TUN.")) {
            Picker(L("Месяц"), selection: $month) {
                ForEach(MonthlyUsage.months(), id: \.self) { Text($0).tag($0) }
            }.frame(width: 220)
            let r = rows
            Card {
                HStack(spacing: 24) {
                    Text(L("Через VPN: %@", human(r.reduce(0) { $0 + $1.vpn })))
                    Text(L("Напрямую: %@", human(r.reduce(0) { $0 + $1.direct })))
                    Text(L("Программ: %d", r.count))
                }.font(.callout.monospacedDigit())
                let maxT = max(1, r.first?.total ?? 1)
                ForEach(r.prefix(40)) { row in
                    HStack {
                        Text(row.id).frame(width: 220, alignment: .leading).lineLimit(1)
                        GeometryReader { g in
                            HStack(spacing: 0) {
                                Rectangle().fill(Slm.accent).frame(width: g.size.width * CGFloat(row.vpn) / CGFloat(maxT))
                                Rectangle().fill(Slm.text3).frame(width: g.size.width * CGFloat(row.direct) / CGFloat(maxT))
                            }
                        }.frame(height: 8)
                        Text(human(row.total)).monospacedDigit().frame(width: 90, alignment: .trailing)
                    }
                }
            }
        }
    }
}

// MARK: Журнал

struct LogView: View {
    @EnvironmentObject var state: AppState
    @State private var lines: [LogLine] = []
    @State private var errorsOnly = false
    private let timer = Timer.publish(every: 1.5, on: .main, in: .common).autoconnect()

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack {
                Text(L("Журнал")).font(.system(size: 24, weight: .semibold))
                Spacer()
                Toggle(L("Только ошибки"), isOn: $errorsOnly)
                Button(L("Скопировать")) { copyToClipboard((state.appLog + lines.map(\.text)).joined(separator: "\n")) }
                Button(L("Очистить")) { SharedLog.clear(); try? Data().write(to: URL(fileURLWithPath: HelperProtocol.tunLogPath)); lines = [] }
            }
            .padding(22)
            ScrollViewReader { proxy in
                ScrollView {
                    LazyVStack(alignment: .leading, spacing: 2) {
                        ForEach(state.appLog.indices, id: \.self) { i in Text(state.appLog[i]).foregroundStyle(Slm.accent2) }
                        ForEach(lines.filter { !errorsOnly || $0.level == "error" }) { l in
                            Text("[\(l.source)] \(l.text)").foregroundStyle(l.level == "error" ? Slm.err : l.level == "warn" ? Slm.warn : Slm.text2)
                        }
                        Color.clear.frame(height: 1).id("end")
                    }
                    .font(.system(.caption, design: .monospaced))
                    .textSelection(.enabled)
                    .padding(.horizontal, 22)
                }
                .onChange(of: lines.count) { _ in proxy.scrollTo("end") }
            }
            .background(Color.black.opacity(0.35))
        }
        .background(Slm.ink)
        .onAppear(perform: load)
        .onReceive(timer) { _ in load() }
    }

    private func load() {
        var l = SharedLog.tail()
        // TUN: sing-box runs as root and logs into the helper's folder.
        if let d = FileManager.default.contents(atPath: HelperProtocol.tunLogPath) {
            l += String(decoding: d.suffix(150_000), as: UTF8.self).split(separator: "\n").map { LogLine(source: "sing-box tun", text: String($0)) }
        }
        lines = Array(l.suffix(1500))
    }
}

// MARK: Ядра

struct CoresView: View {
    @EnvironmentObject var state: AppState
    @State private var versions: [CoreName: String] = [:]
    @State private var latest: [CoreName: Cores.Release] = [:]
    @State private var busy: CoreName?
    @State private var status = ""

    var body: some View {
        Page(title: L("Ядра"), subtitle: L("Ядра скачиваются с официальных страниц релизов на GitHub. Ставится только файл, у которого совпала контрольная сумма SHA-256.")) {
            Card(title: L("Какое ядро запускать")) {
                Toggle(L("Hysteria 2 — официальный клиент вместо sing-box (прыжки по портам)"), isOn: $state.settings.protocols.hysteriaOfficial)
                Toggle(L("NaiveProxy — официальный naive вместо sing-box"), isOn: $state.settings.protocols.naiveOfficial)
            }
            ForEach(CoreName.allCases) { c in
                Card {
                    HStack {
                        VStack(alignment: .leading, spacing: 3) {
                            Text(c.title).font(.headline)
                            Text(c.purpose).font(.caption).foregroundStyle(Slm.text2)
                            Text(L("установлено: %@", versions[c] ?? "—") + (latest[c].map { L("  ·  на GitHub: %@", $0.version) } ?? ""))
                                .font(.caption.monospacedDigit())
                        }
                        Spacer()
                        if c.release != nil {
                            Button(busy == c ? L("Обновляю…") : (latest[c].map { Cores.isNewer($0.version, than: versions[c]) ? L("Обновить") : L("Актуально") } ?? L("Проверить"))) {
                                Task { await update(c) }
                            }
                            .disabled(busy != nil)
                        } else {
                            Text(L("с программой")).font(.caption).foregroundStyle(Slm.text3)
                        }
                    }
                }
            }
            if !status.isEmpty { Text(status).foregroundStyle(Slm.text2) }
            Text(L("sing-box в режиме TUN запускает помощник со своей копией: после обновления sing-box переустановите помощник в настройках."))
                .font(.caption).foregroundStyle(Slm.text2)
        }
        .task { await loadVersions() }
    }

    private func loadVersions() async {
        let v = await Task.detached { Dictionary(uniqueKeysWithValues: CoreName.allCases.map { ($0, Cores.version($0) ?? "—") }) }.value
        versions = v
    }

    private func update(_ c: CoreName) async {
        busy = c
        defer { busy = nil }
        do {
            let r = try await Cores.latest(c)
            latest[c] = r
            if Cores.isNewer(r.version, than: versions[c]) {
                status = L("%@ %@: скачиваю…", c.title, r.version)
                try await Cores.install(r)
                status = L("%@ обновлён до %@.", c.title, r.version)
                await loadVersions()
            } else {
                status = L("%@: последняя версия (%@).", c.title, r.version)
            }
        } catch { status = error.localizedDescription }
    }
}

// MARK: Настройки

struct SettingsView: View {
    @EnvironmentObject var state: AppState

    var body: some View {
        Page(title: L("Настройки")) {
            Card(title: L("Помощник"), note: L("Служба с правами администратора для TUN, системного прокси и kill switch. Ставится один раз, macOS спросит пароль.")) {
                HStack {
                    Pill(text: state.helperInstalled ? L("установлен") : L("не установлен"), color: state.helperInstalled ? Slm.ok : Slm.warn)
                    Button(state.helperInstalled ? L("Переустановить") : L("Установить помощник")) { Task { await state.installHelper() } }
                    if state.helperInstalled {
                        Button(L("Удалить")) {
                            do { try HelperClient.uninstall(); state.show(L("Помощник удалён.")) } catch { state.show(error.localizedDescription) }
                        }
                    }
                }
            }
            Card(title: L("Запуск")) {
                Toggle(L("Запускать вместе с macOS"), isOn: $state.settings.launchAtLogin)
                Toggle(L("Подключаться при запуске"), isOn: $state.settings.autoConnect)
            }
            Card(title: L("Правила по сетям Wi-Fi"), note: L("При смене сети программа сама подключает или отключает VPN. Срабатывает только в момент смены сети.")) {
                Toggle(L("Включить правила по сетям"), isOn: $state.settings.onDemandOn)
                Text(L("Сейчас: %@", state.network.wifi.isEmpty ? (state.network.onCable ? L("кабель") : "—") : state.network.wifi)).font(.callout)
                if state.network.wifi.isEmpty && !state.network.onCable && !state.network.locationAllowed {
                    Button(L("Разрешить видеть название Wi-Fi")) { state.network.askLocation() }
                    Text(L("macOS показывает название сети только программам с доступом к геолокации.")).font(.caption).foregroundStyle(Slm.text2)
                }
                Text(L("Дома без VPN (названия сетей):")).font(.caption).foregroundStyle(Slm.text2)
                LinesEditor(lines: $state.settings.wifiHome, placeholder: "Keenetic-5G", height: 70)
                HStack {
                    Button(L("Добавить текущую сеть")) {
                        let w = state.network.wifi
                        if !w.isEmpty, !state.settings.wifiHome.contains(w) { state.settings.wifiHome.append(w) }
                    }.disabled(state.network.wifi.isEmpty)
                    Toggle(L("В остальных сетях подключать VPN"), isOn: $state.settings.wifiOtherConnect)
                }
            }
            Card(title: L("Локальный прокси")) {
                HStack {
                    Text("127.0.0.1:")
                    TextField("", value: $state.settings.mixedPort, format: .number.grouping(.never)).frame(width: 80)
                    Text(L("HTTP и SOCKS5 на одном порту")).foregroundStyle(Slm.text2)
                }
            }
            Card(title: L("Протоколы")) {
                Toggle(L("Фрагментация TLS (обход DPI)"), isOn: $state.settings.protocols.tlsFragment)
                Toggle(L("Фрагментация TLS-записей"), isOn: $state.settings.protocols.tlsRecordFragment)
                Picker(L("TLS-отпечаток"), selection: $state.settings.protocols.fingerprintOverride) {
                    Text(L("из ссылки")).tag("")
                    ForEach(["chrome", "firefox", "safari", "edge", "ios", "android", "random", "randomized"], id: \.self) { Text($0).tag($0) }
                }.frame(width: 300)
                Picker(L("Мультиплексирование"), selection: $state.settings.protocols.multiplex) {
                    Text(L("выкл.")).tag(""); Text("smux").tag("smux"); Text("yamux").tag("yamux"); Text("h2mux").tag("h2mux")
                }.frame(width: 300)
                HStack {
                    Text("Hysteria ↑/↓, Mbps")
                    TextField("", value: $state.settings.protocols.hysteriaUpMbps, format: .number).frame(width: 60)
                    TextField("", value: $state.settings.protocols.hysteriaDownMbps, format: .number).frame(width: 60)
                }
                Picker(L("Журнал"), selection: $state.settings.logLevel) {
                    ForEach(["error", "warn", "info", "debug"], id: \.self) { Text($0).tag($0) }
                }.frame(width: 300)
            }
            Card(title: L("Обновление программы"), note: L("Новые версии с GitHub Releases, установщик проверяется по SHA-256.")) {
                Text(L("Установлена SLMtune %@", AppUpdater.currentVersion))
                TextField(L("Репозиторий (владелец/имя), пусто — %@", AppUpdater.defaultRepo), text: $state.settings.updateRepo)
                Toggle(L("Проверять раз в сутки"), isOn: $state.settings.updateAuto)
                Toggle(L("Получать бета-версии"), isOn: $state.settings.updateBeta)
                Button(L("Проверить сейчас")) { Task { await state.checkUpdate(silent: false) } }
            }
            Card(title: L("Данные")) {
                Text(AppGroup.container.path).font(.system(.caption, design: .monospaced)).textSelection(.enabled)
                HStack {
                    Button(L("Открыть папку")) { NSWorkspace.shared.open(AppGroup.container) }
                    Button(L("Экспорт настроек…")) { exportSettings() }
                    Button(L("Импорт настроек…")) { importSettings() }
                }
            }
        }
    }

    private func exportSettings() {
        let p = NSSavePanel()
        p.nameFieldStringValue = "slmtune-settings.json"
        guard p.runModal() == .OK, let u = p.url else { return }
        try? SettingsFile.encoded(state.settings).write(to: u)
    }

    private func importSettings() {
        let p = NSOpenPanel()
        p.allowedContentTypes = [.json]
        guard p.runModal() == .OK, let u = p.url, let s = SettingsFile.decode(try? Data(contentsOf: u)) else { return }
        state.settings = s
        state.show(L("Настройки импортированы."))
    }
}
