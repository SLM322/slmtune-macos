import AppKit
import Foundation
import SwiftUI
@testable import SLMShared

/// Everything the windows and the menu bar need: settings (saved at once), the connection, the log.
@MainActor
final class AppState: ObservableObject {
    enum Status: Equatable { case off, connecting, on, stopping }

    @Published var settings: AppSettings { didSet { changed(old: oldValue) } }
    @Published private(set) var status: Status = .off
    @Published private(set) var chain = ""
    @Published private(set) var connectedSince: Date?
    @Published var toast: String?
    @Published var lastError: String?
    @Published var pendingSubscriptionURL: String?
    @Published private(set) var helperInstalled = HelperClient.isInstalled
    @Published private(set) var killSwitchActive = "off"
    @Published var listsUpdating = false
    @Published var availableUpdate: AppUpdater.Update?
    @Published private(set) var appLog: [String] = []

    let runner = CoreRunner()
    let monitor = ClashMonitor()
    let network = NetworkWatcher()
    private var saveTask: Task<Void, Never>?
    private var reconnects = 0
    private var manualDisconnect = false

    init() {
        settings = SettingsFile.load()
        CoreRunner.killLeftovers()
        runner.onCrash = { [weak self] why in self?.coreCrashed(why) }
        network.onChange = { [weak self] wifi in self?.networkChanged(wifi) }
        Task { await self.startUp() }
    }

    private func startUp() async {
        log(L("SLMtune %@ запущен.", AppUpdater.currentVersion))
        if let r = await HelperClient.send(.init(cmd: "ping"), timeout: 3) {
            helperInstalled = true
            killSwitchActive = r.killSwitch
            // A TUN left running by a crash of the app.
            if r.running { _ = await HelperClient.send(.init(cmd: "stop")) }
            if r.version != HelperProtocol.version { log(L("Помощник устарел — переустановите его в настройках.")) }
        }
        await updateLists()
        if settings.autoConnect { connect() }
        schedule()
    }

    // MARK: settings

    private func changed(old: AppSettings) {
        SettingsFile.save(settings)
        saveTask?.cancel()
        let s = settings
        saveTask = Task { [weak self] in
            try? await Task.sleep(nanoseconds: 600_000_000)
            guard let self, !Task.isCancelled else { return }
            if old.preset != s.preset || old.blockLists != s.blockLists { await self.updateLists() }
            if self.status == .on, Self.needsReconnect(old, s) {
                self.log(L("Настройки изменены — переподключаюсь."))
                await self.reconnect()
            }
            if old.launchAtLogin != s.launchAtLogin { try? LoginItem.set(s.launchAtLogin) }
            if old.killSwitch != s.killSwitch || old.killSwitchScope != s.killSwitchScope || old.killSwitchSites != s.killSwitchSites {
                await self.applyKillSwitch(connected: self.status == .on)
            }
        }
    }

    /// Ping results, subscriptions and UI-only fields don't change the cores' configs.
    private static func needsReconnect(_ a: AppSettings, _ b: AppSettings) -> Bool {
        func strip(_ s: AppSettings) -> AppSettings {
            var s = s
            s.servers = s.servers.map { var x = $0; x.pingMs = -1; return x }
            s.subscriptions = []; s.myServers = []
            s.launchAtLogin = false; s.autoConnect = false; s.updateAuto = false; s.updateBeta = false; s.updateSkipped = ""; s.updateRepo = ""
            s.onDemandOn = false; s.wifiHome = []; s.wifiOtherConnect = false; s.killSwitchStrict = false
            return s
        }
        return SettingsFile.encoded(strip(a)) != SettingsFile.encoded(strip(b))
    }

    func show(_ text: String) {
        toast = text
        Task { try? await Task.sleep(nanoseconds: 3_500_000_000); if toast == text { toast = nil } }
    }

    func log(_ line: String) {
        let f = DateFormatter()
        f.dateFormat = "HH:mm:ss"
        appLog.append("\(f.string(from: Date()))  \(line)")
        if appLog.count > 500 { appLog.removeFirst(appLog.count - 500) }
        SharedLog.append("app", line)
    }

    // MARK: connection

    var activeServer: Server? { settings.activeServer }

    func toggle() {
        switch status {
        case .off: manualDisconnect = false; connect()
        case .on, .connecting: Task { await disconnect(manual: true) }
        case .stopping: break
        }
    }

    func connect(zapretOnly: Bool = false) {
        guard status == .off else { return }
        guard zapretOnly || activeServer != nil else { show(L("Сначала добавьте сервер: скопируйте ссылку и нажмите ⌘V.")); return }
        status = .connecting
        lastError = nil
        Task {
            do {
                let server = zapretOnly ? Server(name: "Zapret", kind: "zapret") : activeServer!
                log(zapretOnly ? L("Zapret без VPN: обход DPI для выбранных сайтов.")
                               : L("Подключение к «%@» (%@), режим %@.", server.title, ShareLinks.describe(server), modeTitle(settings.mode)))
                if !Outbounds.hops(settings, server).isEmpty {
                    log(L("Каскад: %@", (Outbounds.hops(settings, server) + [server]).map(\.title).joined(separator: " → ")))
                }
                if settings.killSwitch { await applyKillSwitch(connected: false) }
                let started = try await runner.start(settings, server: server, zapretOnly: zapretOnly) { [weak self] p in self?.log(p) }
                chain = started.description
                if settings.mode == .proxy { await setSystemProxy(true) }
                status = .on
                connectedSince = Date()
                reconnects = 0
                monitor.run(true)
                if settings.killSwitch { await applyKillSwitch(connected: true) }
                log(L("Подключено: %@.", chain))
            } catch {
                await runner.stop()
                status = .off
                lastError = error.localizedDescription
                log(L("Ошибка подключения: %@", error.localizedDescription))
                show(error.localizedDescription)
            }
        }
    }

    func disconnect(manual: Bool) async {
        guard status == .on || status == .connecting else { return }
        manualDisconnect = manual
        status = .stopping
        monitor.run(false)
        if settings.mode == .proxy { await setSystemProxy(false) }
        await runner.stop()
        status = .off
        connectedSince = nil
        chain = ""
        // A deliberate "Отключить" opens the internet again, unless the strict kill switch is on.
        if manual, settings.killSwitch, !settings.killSwitchStrict { await setKillSwitch(off: true) }
        log(L("Отключено."))
    }

    func reconnect() async {
        await disconnect(manual: false)
        connect()
    }

    private func coreCrashed(_ why: String) {
        guard status == .on else { return }
        log(why)
        Task {
            await disconnect(manual: false)
            // Kill switch keeps the internet shut while we retry.
            if reconnects < 5 {
                reconnects += 1
                let delay = UInt64(min(30, 3 * reconnects))
                log(L("Переподключение %d/5 через %d с.", reconnects, Int(delay)))
                try? await Task.sleep(nanoseconds: delay * 1_000_000_000)
                if status == .off { connect() }
            } else {
                show(L("Соединение потеряно. Подробности — в журнале."))
            }
        }
    }

    func modeTitle(_ m: ConnectMode) -> String {
        switch m {
        case .tun: return L("TUN — весь Mac")
        case .proxy: return L("системный прокси")
        case .local: return L("только локальный прокси")
        }
    }

    // MARK: helper-backed system changes

    func installHelper() async {
        do {
            try await HelperClient.install()
            helperInstalled = true
            log(L("Помощник установлен: TUN, системный прокси и kill switch работают без пароля."))
            show(L("Помощник установлен."))
        } catch {
            show(error.localizedDescription)
            log(error.localizedDescription)
        }
    }

    private func setSystemProxy(_ on: Bool) async {
        if helperInstalled, let r = await HelperClient.send(.init(cmd: "proxy").with { $0.on = on; $0.port = settings.mixedPort }), r.ok { return }
        // Without the helper: networksetup asks for the password itself (or works for admins on older macOS).
        let services = ((try? Shell.run("/usr/sbin/networksetup", ["-listallnetworkservices"])) ?? "")
            .split(separator: "\n").dropFirst().map(String.init).filter { !$0.hasPrefix("*") }
        for svc in services {
            if on {
                for k in ["-setwebproxy", "-setsecurewebproxy", "-setsocksfirewallproxy"] {
                    _ = try? Shell.run("/usr/sbin/networksetup", [k, svc, "127.0.0.1", "\(settings.mixedPort)"])
                }
            } else {
                for k in ["-setwebproxystate", "-setsecurewebproxystate", "-setsocksfirewallproxystate"] {
                    _ = try? Shell.run("/usr/sbin/networksetup", [k, svc, "off"])
                }
            }
        }
    }

    /// Kill switch on pf through the helper. `connected`: also lets the VPN servers' own addresses through.
    func applyKillSwitch(connected: Bool) async {
        guard settings.killSwitch else { await setKillSwitch(off: true); return }
        guard helperInstalled else { log(L("Kill switch работает через помощник — установите его в настройках.")); return }
        var servers: [String] = []
        if let s = activeServer {
            let all = Outbounds.hops(settings, s) + [s] + s.members.compactMap { settings.server($0) }
            for srv in all where !srv.server.isEmpty {
                servers += await Self.resolve(srv.server)
                for a in srv.param("addresses").split(separator: "\n") {
                    servers += await Self.resolve(String(a.split(separator: ":").dropLast().joined(separator: ":")).trimmingCharacters(in: CharacterSet(charactersIn: "[]")))
                }
            }
        }
        var blocked: [String] = []
        if settings.killSwitchScope == "selected" {
            for e in settings.killSwitchSites {
                let t = e.trimmingCharacters(in: .whitespaces)
                if MacRules.isAddress(t) { blocked.append(t) } else if !t.isEmpty {
                    blocked += await Self.resolve(MacRules.clean(t)) + Self.resolveSync("www." + MacRules.clean(t))
                }
            }
        }
        let req = HelperProtocol.Request(cmd: "killswitch").with {
            $0.scope = settings.killSwitchScope; $0.servers = servers; $0.allowLan = settings.excludeLocalNetworks; $0.blocked = blocked
        }
        if let r = await HelperClient.send(req) {
            killSwitchActive = r.killSwitch
            if !r.ok { log(L("Kill switch не включился: %@", r.message)) }
            else { log(settings.killSwitchScope == "all" ? L("Kill switch: без VPN интернет закрыт.") : L("Kill switch: выбранное без VPN закрыто.")) }
        }
    }

    func setKillSwitch(off: Bool) async {
        guard helperInstalled, killSwitchActive != "off" else { return }
        if let r = await HelperClient.send(.init(cmd: "killswitch").with { $0.scope = "off" }) {
            killSwitchActive = r.killSwitch
            log(L("Kill switch выключен: интернет без VPN снова открыт."))
        }
    }

    nonisolated static func resolve(_ host: String) async -> [String] {
        await Task.detached { resolveSync(host) }.value
    }

    nonisolated static func resolveSync(_ host: String) -> [String] {
        if MacRules.isAddress(host) { return [host] }
        var hints = addrinfo(ai_flags: 0, ai_family: AF_UNSPEC, ai_socktype: SOCK_STREAM, ai_protocol: 0, ai_addrlen: 0, ai_canonname: nil, ai_addr: nil, ai_next: nil)
        var res: UnsafeMutablePointer<addrinfo>?
        guard getaddrinfo(host, nil, &hints, &res) == 0 else { return [] }
        defer { freeaddrinfo(res) }
        var out: [String] = []
        var p = res
        while let a = p {
            var buf = [CChar](repeating: 0, count: Int(NI_MAXHOST))
            if getnameinfo(a.pointee.ai_addr, a.pointee.ai_addrlen, &buf, socklen_t(buf.count), nil, 0, NI_NUMERICHOST) == 0 {
                out.append(String(cString: buf))
            }
            p = a.pointee.ai_next
        }
        return Array(Set(out))
    }

    // MARK: rules by network

    private func networkChanged(_ wifi: String) {
        guard settings.onDemandOn else { return }
        let home = !wifi.isEmpty && settings.wifiHome.contains { $0.caseInsensitiveCompare(wifi) == .orderedSame }
        if home, status == .on {
            log(L("Сеть «%@»: по правилу отключаю VPN.", wifi))
            Task { await disconnect(manual: true) }
        } else if !home, settings.wifiOtherConnect, status == .off, activeServer != nil {
            log(L("Сеть «%@»: по правилу подключаю VPN.", wifi.isEmpty ? L("кабель") : wifi))
            connect()
        }
    }

    // MARK: servers

    func select(_ s: Server) {
        settings.activeId = s.id
        if status == .on { Task { await reconnect() } }
    }

    func add(_ list: [Server]) {
        settings.servers += list
        if settings.activeId.isEmpty, let f = settings.servers.first { settings.activeId = f.id }
    }

    func remove(_ ids: Set<String>) {
        settings.servers.removeAll { ids.contains($0.id) }
        for i in settings.servers.indices {
            if ids.contains(settings.servers[i].viaId) { settings.servers[i].viaId = "" }
            settings.servers[i].members.removeAll { ids.contains($0) }
        }
        if ids.contains(settings.cascadeEntryId) { settings.cascadeEntryId = "" }
        if ids.contains(settings.activeId) { settings.activeId = settings.servers.first?.id ?? "" }
    }

    func update(_ s: Server) {
        if let i = settings.servers.firstIndex(where: { $0.id == s.id }) { settings.servers[i] = s }
    }

    // MARK: import

    func importText(_ text: String) {
        switch Importer.parse(text) {
        case .servers(let list, let failed):
            add(list)
            if list.isEmpty { show(failed.first ?? L("Ссылки не распознаны.")) }
            else if failed.isEmpty { show(L("Добавлено серверов: %d", list.count)) }
            else { show(L("Добавлено: %d, не распознано: %d", list.count, failed.count)) }
        case .subscription(let url):
            pendingSubscriptionURL = url
        case .nothing(let why):
            show(why)
        }
    }

    func pasteFromClipboard() {
        importText(NSPasteboard.general.string(forType: .string) ?? "")
    }

    func importFromScreen() {
        guard ScreenQR.screenAccess else {
            ScreenQR.askScreenAccess()
            show(L("Разрешите SLMtune запись экрана (Системные настройки → Конфиденциальность), затем повторите."))
            return
        }
        let codes = ScreenQR.readScreens()
        if codes.isEmpty { show(L("На экране не найден QR-код. Откройте его крупнее и повторите.")); return }
        importText(codes.joined(separator: "\n"))
    }

    func addWarp(obfuscate: Bool) async {
        do {
            let s = try await Warp.register(obfuscate: obfuscate)
            add([s])
            show(L("Добавлен «%@».", s.title))
        } catch { show(error.localizedDescription) }
    }

    // MARK: subscriptions

    func addSubscription(url: String, name: String = "") async {
        var sub = Subscription(name: name, url: url)
        settings.subscriptions.append(sub)
        await refresh(&sub)
    }

    func refreshAll(includeManual: Bool = false) async {
        for var sub in settings.subscriptions where sub.autoUpdate || includeManual { await refresh(&sub) }
    }

    func refresh(_ sub: inout Subscription) async {
        do {
            let r = try await Subscriptions.fetch(sub)
            sub = r.sub
            let old = settings.servers.filter { $0.subscriptionId == sub.id }
            let fresh = r.servers.map { n -> Server in
                var n = n
                if let o = old.first(where: { $0.server == n.server && $0.port == n.port && $0.kind == n.kind && $0.name == n.name }) {
                    n.id = o.id; n.viaId = o.viaId; n.pingMs = o.pingMs
                }
                return n
            }
            settings.servers = settings.servers.filter { $0.subscriptionId != sub.id } + fresh
            if settings.server(settings.activeId) == nil { settings.activeId = settings.servers.first?.id ?? "" }
            log(L("Подписка «%@»: %d серверов", sub.name, fresh.count))
            let info = Subscriptions.describe(sub)
            if !info.isEmpty { log(L("Подписка «%@», трафик и срок: %@.", sub.name, info)) }
            if sub.expire > 0, Date(timeIntervalSince1970: TimeInterval(sub.expire)).timeIntervalSinceNow < 3 * 86400 {
                show(L("Подписка «%@» скоро закончится: %@.", sub.name, info))
            } else if sub.total > 0, sub.upload + sub.download >= sub.total * 9 / 10 {
                show(L("Подписка «%@»: израсходовано 90 %% трафика.", sub.name))
            }
        } catch {
            sub.lastError = error.localizedDescription
            show(error.localizedDescription)
        }
        let id = sub.id
        if let i = settings.subscriptions.firstIndex(where: { $0.id == id }) { settings.subscriptions[i] = sub }
    }

    // MARK: lists, ping, updates

    func updateLists(force: Bool = false) async {
        listsUpdating = true
        let n = await Lists.update(settings, force: force)
        listsUpdating = false
        if n > 0, status == .on { await reconnect() }
        if force { show(n > 0 ? L("Списки обновлены: %d", n) : L("Списки уже свежие или недоступны.")) }
    }

    func pingAll() async {
        for i in settings.servers.indices where Pinger.udpOnly.contains(settings.servers[i].kind) { settings.servers[i].pingMs = -3 }
        let list = settings.servers.filter { !["group", "tor", "zapret"].contains($0.kind) && !Pinger.udpOnly.contains($0.kind) }
        await withTaskGroup(of: (String, Int).self) { g in
            for s in list { g.addTask { (s.id, await Pinger.tcp(host: s.server, port: s.port)) } }
            for await (id, ms) in g {
                if let i = settings.servers.firstIndex(where: { $0.id == id }) { settings.servers[i].pingMs = ms }
            }
        }
    }

    func checkUpdate(silent: Bool) async {
        do {
            guard let u = try await AppUpdater.check(settings) else {
                if !silent { show(L("SLMtune %@ — последняя версия.", AppUpdater.currentVersion)) }
                return
            }
            if silent, u.version == settings.updateSkipped { return }
            availableUpdate = u
            log(L("Вышла SLMtune %@.", u.version))
        } catch {
            if !silent { show(error.localizedDescription) }
        }
    }

    func installUpdate(_ u: AppUpdater.Update) async {
        do {
            show(L("Скачиваю SLMtune %@…", u.version))
            if status != .off { await disconnect(manual: false) }
            try await AppUpdater.install(u)
            NSApp.terminate(nil)
        } catch { show(error.localizedDescription) }
    }

    /// Subscriptions every 12 h, lists daily, self-update daily.
    private func schedule() {
        Task {
            while true {
                try? await Task.sleep(nanoseconds: 60 * 60 * 1_000_000_000)
                await refreshAll()
                await updateLists()
                if settings.updateAuto { await checkUpdate(silent: true) }
            }
        }
        if settings.updateAuto { Task { try? await Task.sleep(nanoseconds: 20_000_000_000); await checkUpdate(silent: true) } }
    }

    /// Quitting: everything stops, the system proxy is put back; the kill switch stays only in strict mode.
    func shutdown() async {
        await disconnect(manual: true)
        monitor.usage.save()
    }
}
