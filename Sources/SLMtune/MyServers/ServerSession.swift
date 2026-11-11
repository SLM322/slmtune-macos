import Foundation
@testable import SLMShared

/// One "Мой сервер" while its screen is open: SSH runs, the probe, applying protocols and users, tools.
/// Same checks and order as ServerWindow (Windows) and ServerSession.kt (Android). The password lives only in memory.
@MainActor
final class ServerSession: ObservableObject {
    @Published var server: MyServer
    @Published var password = ""
    @Published private(set) var log: [String] = []
    @Published private(set) var info: ServerInfo?
    @Published private(set) var cfg: MyServerConfig?
    @Published private(set) var busy = false
    /// Bumped after every change so views redraw the (reference-type) config.
    @Published private(set) var version = 0

    static let protocols: [(key: String, title: String)] = [
        ("vless", "VLESS Reality"), ("hy2", "Hysteria2"), ("ss", "Shadowsocks 2022"), ("naive", "NaiveProxy"), ("tt", "TrustTunnel"),
        ("trojan", "Trojan"), ("tuic", "TUIC"), ("anytls", "AnyTLS"), ("vless_ws", "VLESS WebSocket"), ("vless_grpc", "VLESS gRPC"),
        ("socks", "SOCKS5 (для Telegram)"), ("shadowtls", "ShadowTLS"),
    ]
    /// Need a domain with a certificate (Let's Encrypt; TrustTunnel uses its own pinned one).
    static let withDomain: Set<String> = ["naive", "tt", "trojan", "tuic", "anytls", "vless_ws", "vless_grpc"]
    private static let acmeKeys: Set<String> = ["naive", "trojan", "tuic", "anytls", "vless_ws", "vless_grpc"]

    init(_ server: MyServer) { self.server = server }

    static func value(_ output: String, _ key: String) -> String? {
        output.split(separator: "\n").last { $0.hasPrefix("\(key)=") }.map { String($0.dropFirst(key.count + 1)).trimmingCharacters(in: .whitespaces) }
    }

    /// Long machine lines (base64 configs, port lists) stay out of the visible log.
    private static func loggable(_ l: String) -> Bool {
        !(l.hasPrefix("config=") || l.hasPrefix("meta=") || l.hasPrefix("usage=") || l.hasPrefix("listen=") || l.count > 400)
    }

    func addLog(_ line: String) {
        log.append(line)
        if log.count > 300 { log.removeFirst(log.count - 300) }
    }

    private var target: SSH.Target {
        SSH.Target(host: server.host, port: server.port, user: server.user, hostKey: server.hostKey,
                   password: password.isEmpty ? nil : password)
    }

    func run(_ script: String, _ title: String) async throws -> String {
        addLog("— " + title)
        if password.isEmpty, !server.keyInstalled { throw SSH.Failed(L("Введите пароль сервера: ключ программы ещё не на сервере.")) }
        busy = true
        defer { busy = false }
        let (code, out) = try await SSH.run(target, script: script) { line in
            Task { @MainActor in if Self.loggable(line) { self.addLog(line) } }
        }
        if code != 0 { throw SSH.Failed(L("Команда на сервере завершилась с ошибкой (код %d) — подробности в журнале.", code)) }
        return out
    }

    func probe() async throws {
        let out = try await run(ServerScripts.probe, L("проверяю сервер"))
        let i = ServerInfo.parse(out)
        info = i
        cfg = MyServerConfig.from(i)
        version += 1
        addLog(L("Сервер: %@ · %@", i.os, i.arch) + (i.singBox.isEmpty ? L(" · sing-box не установлен") : " · sing-box \(i.singBox)"))
    }

    /// Puts the app's key into authorized_keys (with the password), so later logins need nothing.
    func installKey() async throws -> Bool {
        let out = try await run(ServerScripts.installKey(SSH.publicKeyLine()), L("кладу ключ программы на сервер"))
        return out.contains("key=ok")
    }

    struct Plan {
        var ports: [String: Int]
        var domain: String
        var sni: String
        var bbr: Bool
    }

    private static func isDomain(_ s: String) -> Bool {
        s.range(of: #"^[a-z0-9.-]+\.[a-z]{2,}$"#, options: [.regularExpression, .caseInsensitive]) != nil
    }

    /// What's wrong with the plan, in words for the user, or nil.
    func check(_ p: Plan) -> String? {
        guard let i = info, let c = cfg else { return L("Сначала подключитесь к серверу.") }
        if p.ports.values.contains(where: { !(1...65535).contains($0) }) { return L("Неверный порт.") }
        let keys = Set(p.ports.keys)
        let acme = !keys.isDisjoint(with: Self.acmeKeys)
        if (acme || keys.contains("tt")) && !Self.isDomain(p.domain) {
            return L("Для TrustTunnel, NaiveProxy, Trojan, TUIC, AnyTLS и VLESS WS/gRPC нужен домен, например 1-2-3-4.sslip.io.")
        }
        if keys.isEmpty && !c.anyProtocol { return L("Отметьте хотя бы один протокол.") }
        if keys.contains("anytls"), !i.singBox.isEmpty, !MyServerConfig.supportsAnyTls(i.singBox) {
            return L("AnyTLS появился в sing-box 1.12, а на сервере стоит %@. Обновите sing-box в «Инструментах» или снимите AnyTLS.", i.singBox)
        }
        var wanted: [(Int, String)] = []
        for (k, port) in p.ports {
            switch k {
            case "hy2", "tuic": wanted.append((port, "udp"))
            case "ss", "tt", "socks": wanted += [(port, "tcp"), (port, "udp")]
            default: wanted.append((port, "tcp"))
            }
        }
        for (port, proto) in wanted {
            guard let owner = i.portOwner(port, proto) else { continue }
            if owner.hasPrefix("trusttunnel"), i.ttManaged, keys.contains("tt"), port == p.ports["tt"] { continue }
            return L("Порт %d/%@ на сервере занят программой %@. Выберите другой.", port, proto, owner)
        }
        if Set(wanted.map { "\($0.0)/\($0.1)" }).count != wanted.count { return L("Два протокола на одном порту. Выберите разные порты.") }
        if (keys.contains("vless") || keys.contains("shadowtls")) && !Self.isDomain(p.sni) {
            return L("Сайт для маскировки — доменное имя, например www.microsoft.com.")
        }
        if acme, !c.needsAcme, let owner = i.portOwner(80, "tcp") {
            return L("Порт 80 на сервере занят программой %@ — Let's Encrypt не сможет выдать сертификат.", owner)
        }
        return nil
    }

    func apply(_ p: Plan) async throws {
        guard let i = info, let c = cfg else { return }
        let oldPorts = Set(c.ports())
        let hadTt = c.has("tt"), hadAcme = c.needsAcme
        let keys = Set(p.ports.keys)
        let acme = !keys.isDisjoint(with: Self.acmeKeys)
        let needKeys = keys.contains("vless") && c.vlessNeedsKeys
        let wantSingBox = keys.contains { $0 != "tt" }
        var priv: String?, pub: String?
        if wantSingBox && (i.singBox.isEmpty || needKeys) {
            let out = try await run(ServerScripts.ensureSingBox(realityKeys: needKeys), L("ставлю sing-box"))
            c.singBoxVersion = Self.value(out, "singbox") ?? c.singBoxVersion
            priv = Self.value(out, "reality_private")
            pub = Self.value(out, "reality_public")
            if needKeys && (priv ?? "").isEmpty { throw SSH.Failed(L("sing-box не выдал ключи Reality — подробности в журнале.")) }
            if keys.contains("anytls"), !MyServerConfig.supportsAnyTls(c.singBoxVersion) {
                throw SSH.Failed(L("AnyTLS появился в sing-box 1.12, а на сервере стоит %@.", c.singBoxVersion))
            }
        }
        for (k, _) in Self.protocols {
            guard let port = p.ports[k] else { c.remove(k); continue }
            switch k {
            case "vless": c.setVless(port, sni: p.sni, privateKey: priv, publicKey: pub)
            case "hy2": try c.setHy2(port)
            case "ss": c.setSs(port)
            case "tt": try c.setTt(port, p.domain)
            case "vless_ws": c.setVlessWs(port, p.domain)
            case "vless_grpc": c.setVlessGrpc(port, p.domain)
            case "socks": c.setSocks(port)
            case "shadowtls": c.setShadowTls(port, p.sni)
            default: c.setPlain(k, port: port, domain: p.domain) // naive, trojan, tuic, anytls
            }
        }
        if c.users.isEmpty { try c.addUser("me") }
        let newPorts = Set(c.ports())
        var open = Array(newPorts.subtracting(oldPorts))
        if acme && !hadAcme { open.append("80/tcp") } // Let's Encrypt; never closed (others may need it)
        let singBox = c.hasSingBoxProtocols || !i.singBox.isEmpty
        _ = try await run(applyScript(open: open, close: Array(oldPorts.subtracting(newPorts)), bbr: p.bbr, singBox: singBox),
                          L("применяю настройки на сервере"))
        if c.has("tt") {
            _ = try await run(ServerScripts.ttApply(vpn: c.ttVpnToml(), hosts: c.ttHostsToml(), creds: c.ttCredentialsToml(),
                                                    cert: c.str("tt", "cert"), key: c.str("tt", "key")), L("ставлю и настраиваю TrustTunnel"))
        } else if hadTt {
            _ = try await run(ServerScripts.ttRemove, L("выключаю TrustTunnel"))
        }
        try await probe()
        if acme && !hadAcme { addLog(L("Сертификат Let's Encrypt придёт в течение минуты — до этого протоколы с сертификатом не подключатся.")) }
    }

    private func applyScript(open: [String], close: [String], bbr: Bool, singBox: Bool) -> String {
        let c = cfg!
        return ServerScripts.apply(config: c.configJson(), meta: c.metaJson(), open: open, close: close, bbr: bbr,
                                   singBox: singBox, nft: c.hasSingBoxProtocols ? c.nftRules() : nil)
    }

    /// Users changed: every protocol gets the new list (sing-box restarts, connections re-establish).
    func applyUsers() async throws {
        guard let c = cfg else { return }
        _ = try await run(applyScript(open: [], close: [], bbr: false, singBox: c.hasSingBoxProtocols), L("обновляю пользователей"))
        if c.has("tt") {
            _ = try await run(ServerScripts.ttApply(vpn: c.ttVpnToml(), hosts: c.ttHostsToml(), creds: c.ttCredentialsToml(),
                                                    cert: c.str("tt", "cert"), key: c.str("tt", "key")), L("обновляю пользователей TrustTunnel"))
        }
        try await probe()
    }

    /// Only limits, dates or notes changed: nothing restarts, nobody is disconnected.
    func applyLimits() async throws {
        _ = try await run(applyScript(open: [], close: [], bbr: false, singBox: false), L("сохраняю лимиты"))
        try await probe()
    }

    func resetUsage(_ u: MyUser) async throws {
        _ = try await run(ServerScripts.resetUsage(u.id), L("обнуляю трафик %@", u.name))
        try await probe()
    }

    func changed() { version += 1 }
}
