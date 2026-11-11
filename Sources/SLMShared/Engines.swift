import Foundation

/// Servers that sing-box can't speak itself run on an extra core inside the Packet Tunnel process
/// (the Windows/Android "separate core" scheme, without separate processes): each core listens on
/// 127.0.0.1:<port> as SOCKS5 and sing-box routes to it with a socks outbound.
///
/// - Xray (in the Go framework): VLESS XHTTP, VLESS Encryption;
/// - mihomo (in the Go framework): AmneziaWG, mieru, ShadowsocksR;
/// - TrustTunnel (AdGuard's C++ client, SOCKS mode);
/// - Tor (Tor.framework) with obfs4 / webtunnel / meek / snowflake from the Go framework.
enum Engine: String, Codable, CaseIterable {
    case xray, mihomo, trusttunnel, tor, hysteria, naive

    var title: String {
        switch self {
        case .xray: return "Xray"
        case .mihomo: return "mihomo"
        case .trusttunnel: return "TrustTunnel"
        case .tor: return "Tor"
        case .hysteria: return "Hysteria 2"
        case .naive: return "NaiveProxy"
        }
    }
}

enum Engines {
    /// Which extra core a server needs, or nil when sing-box handles it.
    /// macOS: official cores chosen in Settings → Ядра (set by the app before building a config).
    static var official: Set<Engine> = []

    static func engine(_ s: Server) -> Engine? {
        switch s.kind {
        case "hysteria2": return official.contains(.hysteria) ? .hysteria : nil
        case "naive": return official.contains(.naive) ? .naive : nil
        case "tt": return .trusttunnel
        case "tor": return .tor
        case "amneziawg", "mieru", "ssr": return .mihomo
        case "vless": return ShareLinks.needsXray(s.params) ? .xray : nil
        default: return nil
        }
    }

    /// Every server of the connection that needs an extra core: the cascade hops and group members.
    static func backends(_ settings: AppSettings, _ server: Server) -> [Server] {
        let list = Outbounds.hops(settings, server) + [server]
        let expanded = list.flatMap { s -> [Server] in
            s.kind == "group" ? s.members.compactMap { settings.server($0) } : [s]
        }
        var seen = Set<String>()
        return expanded.filter { engine($0) != nil && seen.insert($0.id).inserted }
    }

    private static func json(_ o: JSON) -> String {
        let d = (try? JSONSerialization.data(withJSONObject: o, options: [.sortedKeys, .withoutEscapingSlashes])) ?? Data()
        return String(decoding: d, as: UTF8.self)
    }

    // MARK: Xray

    /// SOCKS inbound on 127.0.0.1:port, VLESS outbound from the link (port of ShareLinks.ToXrayConfig).
    static func xrayConfig(_ s: Server, port: Int, logLevel: String) -> String {
        var net = s.param("type", "tcp").lowercased()
        if net == "splithttp" { net = "xhttp" }
        if net == "tcp" { net = "raw" }
        let sec = s.param("security", "none").lowercased()
        let sni = s.param("sni", s.param("host")).isEmpty ? s.server : s.param("sni", s.param("host"))
        let fp = s.param("fp", "chrome")
        var stream: JSON = ["network": net, "security": sec]
        if sec == "reality" {
            var r: JSON = ["serverName": sni, "fingerprint": fp, "publicKey": s.param("pbk"),
                           "shortId": s.param("sid"), "spiderX": s.param("spx", "/")]
            if !s.param("pqv").isEmpty { r["mldsa65Verify"] = s.param("pqv") }
            stream["realitySettings"] = r
        } else if sec == "tls" {
            var t: JSON = ["serverName": sni, "fingerprint": fp,
                           "allowInsecure": ["1", "true"].contains(s.param("allowInsecure").lowercased())]
            let alpn = Outbounds.csv(s.param("alpn"))
            if !alpn.isEmpty { t["alpn"] = alpn }
            stream["tlsSettings"] = t
        }
        switch net {
        case "xhttp":
            var x: JSON = ["path": s.param("path", "/"), "mode": s.param("mode", "auto"), "xPaddingBytes": "100-1000"]
            if !s.param("host").isEmpty { x["host"] = s.param("host") }
            // "extra" from the link (downloadSettings, xmux…) goes in as is.
            if let e = s.param("extra").data(using: .utf8), let extra = try? JSONSerialization.jsonObject(with: e) as? JSON {
                x["extra"] = extra
            }
            stream["xhttpSettings"] = x
        case "grpc":
            stream["grpcSettings"] = ["serviceName": s.param("serviceName", s.param("path"))]
        case "ws":
            stream["wsSettings"] = ["path": s.param("path", "/"), "headers": ["Host": s.param("host")]] as JSON
        case "httpupgrade":
            stream["httpupgradeSettings"] = ["path": s.param("path", "/"), "host": s.param("host")]
        default: break
        }
        var user: JSON = ["id": s.userId, "encryption": s.param("encryption", "none")]
        if !s.param("flow").isEmpty { user["flow"] = s.param("flow") }
        let level: String
        switch logLevel { case "debug": level = "debug"; case "info": level = "info"; case "error": level = "error"; default: level = "warning" }
        return json([
            "log": ["loglevel": level],
            "inbounds": [[
                "tag": "socks-in", "listen": "127.0.0.1", "port": port, "protocol": "socks",
                "settings": ["udp": true, "auth": "noauth"] as JSON,
            ] as JSON],
            "outbounds": [[
                "tag": "proxy", "protocol": "vless",
                "settings": ["vnext": [["address": s.server, "port": s.port, "users": [user]] as JSON]],
                "streamSettings": stream,
            ] as JSON],
        ])
    }

    // MARK: mihomo

    /// One mihomo config for every mihomo server of the connection (mihomo is a singleton): each proxy gets
    /// its own mixed listener on 127.0.0.1 (port of MoreProtocols.ToMihomoConfig).
    static func mihomoConfig(_ entries: [(server: Server, port: Int)], logLevel: String) -> String {
        var proxies: [JSON] = [], listeners: [JSON] = []
        for (i, e) in entries.enumerated() {
            let name = "p\(i)"
            proxies.append(mihomoProxy(e.server, name: name))
            listeners.append(["name": "in\(i)", "type": "mixed", "listen": "127.0.0.1", "port": e.port, "proxy": name, "udp": true])
        }
        let level: String
        switch logLevel { case "debug": level = "debug"; case "info": level = "info"; case "error": level = "error"; default: level = "warning" }
        return json([
            "mode": "rule", "allow-lan": false, "ipv6": true, "log-level": level,
            "geo-auto-update": false, "unified-delay": true,
            "proxies": proxies, "listeners": listeners, "rules": ["MATCH,DIRECT"],
        ])
    }

    static func mihomoProxy(_ s: Server, name: String) -> JSON {
        var p: JSON = ["name": name, "server": s.server, "port": s.port, "udp": true]
        switch s.kind {
        case "amneziawg":
            p["type"] = "wireguard"
            let addrs = Outbounds.csv(s.param("address"))
            if let v4 = addrs.first(where: { !$0.contains(":") }) { p["ip"] = v4.components(separatedBy: "/")[0] }
            if let v6 = addrs.first(where: { $0.contains(":") }) { p["ipv6"] = v6.components(separatedBy: "/")[0] }
            p["private-key"] = s.password
            p["public-key"] = s.param("publickey")
            if !s.param("presharedkey").isEmpty { p["pre-shared-key"] = s.param("presharedkey") }
            p["allowed-ips"] = Outbounds.csv(s.param("allowedips", "0.0.0.0/0, ::/0"))
            p["mtu"] = Int(s.param("mtu")) ?? 1280
            p["persistent-keepalive"] = Int(s.param("keepalive")) ?? 25
            let reserved = Outbounds.csv(s.param("reserved")).compactMap { Int($0) }
            if reserved.count == 3 { p["reserved"] = reserved }
            var awg: JSON = [:]
            for key in MoreLinks.awgKeys {
                let v = s.param(key)
                if v.isEmpty { continue }
                // i1…i5 and j1…j3 are strings (packet templates), the rest numbers.
                let isString = ["i1", "i2", "i3", "i4", "i5", "j1", "j2", "j3"].contains(key) // not "jc"
                awg[key] = isString ? v : (Int(v).map { $0 as Any } ?? v)
            }
            p["amnezia-wg-option"] = awg
        case "mieru":
            p["type"] = "mieru"
            p["transport"] = s.param("protocol", "TCP").uppercased() == "UDP" ? "UDP" : "TCP"
            p["username"] = s.userId
            p["password"] = s.password
            if !s.param("multiplexing").isEmpty { p["multiplexing"] = s.param("multiplexing") }
        case "ssr":
            p["type"] = "ssr"
            p["cipher"] = s.userId
            p["password"] = s.password
            p["obfs"] = s.param("obfs", "plain")
            p["protocol"] = s.param("protocol", "origin")
            if !s.param("obfsparam").isEmpty { p["obfs-param"] = s.param("obfsparam") }
            if !s.param("protoparam").isEmpty { p["protocol-param"] = s.param("protoparam") }
        default: break
        }
        return p
    }

    // MARK: TrustTunnel

    private static func tq(_ v: String) -> String {
        "\"" + v.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "\"", with: "\\\"")
            .replacingOccurrences(of: "\n", with: "\\n") + "\""
    }

    /// TrustTunnel client TOML with a SOCKS listener (port of ExtraCores.ttConfig).
    static func ttConfig(_ s: Server, port: Int) -> String {
        let addresses = s.param("addresses").components(separatedBy: "\n").map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }
        var t = """
        loglevel = "info"
        vpn_mode = "general"
        killswitch_enabled = false
        killswitch_allow_ports = []
        post_quantum_group_enabled = true
        exclusions = []

        [endpoint]
        hostname = \(tq(s.server))
        addresses = [\(addresses.map(tq).joined(separator: ", "))]

        """
        if !s.param("sni").isEmpty { t += "custom_sni = \(tq(s.param("sni")))\n" }
        t += """
        has_ipv6 = \(s.param("ipv6") != "0")
        username = \(tq(s.userId))
        password = \(tq(s.password))
        client_random = \(tq(s.param("random")))
        skip_verification = \(s.param("skip") == "1")
        certificate = \(tq(s.param("cert")))
        upstream_protocol = \(tq(s.param("upstream", "http2")))
        tls_profile = "chrome"
        anti_dpi = \(s.param("antidpi") == "1")
        dns_upstreams = ["tls://1.1.1.1", "tls://8.8.8.8"]

        [listener.socks]
        address = \(tq("127.0.0.1:\(port)"))

        """
        return t
    }

    // MARK: Tor

    /// Built-in bridges and transports from Tor Browser's pt_config.json (Resources, refreshed by
    /// scripts/update-tor-bridges.sh).
    static func builtInBridges(_ transport: String) -> [String] {
        guard let url = Bundle.main.url(forResource: "pt_config", withExtension: "json"),
              let data = try? Data(contentsOf: url),
              let root = try? JSONSerialization.jsonObject(with: data) as? JSON,
              let bridges = root["bridges"] as? [String: [String]] else { return [] }
        return bridges[transport] ?? []
    }

    /// The transport name a bridge line starts with ("obfs4 1.2.3.4:443 …" → obfs4; meek → meek_lite).
    static func bridgeTransport(_ line: String) -> String {
        let first = line.split(separator: " ").first.map(String.init) ?? ""
        return first.contains(".") || first.contains(":") ? "" : first
    }

    /// Bridges for a Tor server: built-in for snowflake/obfs4/meek, the user's own for webtunnel/custom.
    static func torBridges(_ s: Server) throws -> [String] {
        let transport = s.param("transport", "snowflake")
        if transport == "none" { return [] }
        if transport == "custom" || transport == "webtunnel" {
            let own = s.param("bridges").components(separatedBy: "\n").map { $0.trimmingCharacters(in: .whitespaces) }
                .filter { !$0.isEmpty && !$0.hasPrefix("#") }
                .map { $0.lowercased().hasPrefix("bridge ") ? String($0.dropFirst(7)) : $0 }
            if own.isEmpty { throw LinkError(L("Добавьте мосты Tor: их выдают на bridges.torproject.org и в Telegram-боте @GetBridgesBot.")) }
            return own
        }
        let list = builtInBridges(transport)
        if list.isEmpty { throw LinkError(L("Нет встроенных мостов %@. Укажите свои мосты.", transport)) }
        return list
    }

    /// tor command-line arguments: SOCKS on 127.0.0.1:socksPort, bridges through the in-process transports.
    static func torArguments(socksPort: Int, dataDir: String, logFile: String, bridges: [String], transportPorts: [String: Int]) -> [String] {
        var a = ["--SocksPort", "127.0.0.1:\(socksPort)", "--DataDirectory", dataDir,
                 "--ClientOnly", "1", "--AvoidDiskWrites", "1", "--Log", "notice file \(logFile)"]
        if !bridges.isEmpty {
            a += ["--UseBridges", "1"]
            for (name, port) in transportPorts.sorted(by: { $0.key < $1.key }) {
                a += ["--ClientTransportPlugin", "\(name) socks5 127.0.0.1:\(port)"]
            }
            for b in bridges { a += ["--Bridge", b] }
        }
        return a
    }
}


// MARK: macOS official cores

extension Engines {
    /// Config for the official Hysteria 2 client: SOCKS5 on 127.0.0.1:port (port of ExtraCores.HysteriaConfig).
    static func hysteriaConfig(_ s: Server, port: Int, caFile: String?, ps: ProtocolSettings) -> String {
        let host = s.server.contains(":") ? "[\(s.server)]" : s.server
        let hop = s.param("mport", s.param("ports"))
        var cfg: JSON = [
            "server": hop.isEmpty ? "\(host):\(s.port)" : "\(host):\(hop.replacingOccurrences(of: " ", with: ","))",
            "auth": s.password,
            "socks5": ["listen": "127.0.0.1:\(port)", "disableUDP": false] as JSON,
            "fastOpen": true, "lazy": false,
        ]
        var tls: JSON = ["sni": s.param("sni", s.server)]
        if let ca = caFile { tls["ca"] = ca }
        else {
            if !s.param("pinSHA256").isEmpty { tls["pinSHA256"] = s.param("pinSHA256") }
            if ["1", "true"].contains(s.param("insecure").lowercased()) { tls["insecure"] = true }
        }
        cfg["tls"] = tls
        if s.param("obfs") == "salamander" {
            cfg["obfs"] = ["type": "salamander", "salamander": ["password": s.param("obfs-password")] as JSON] as JSON
        }
        if ps.hysteriaUpMbps > 0 || ps.hysteriaDownMbps > 0 {
            cfg["bandwidth"] = ["up": "\(max(1, ps.hysteriaUpMbps)) mbps", "down": "\(max(1, ps.hysteriaDownMbps)) mbps"] as JSON
        }
        if !hop.isEmpty { cfg["transport"] = ["udp": ["hopInterval": "30s"] as JSON] as JSON }
        return json(cfg)
    }

    /// Config for the official naive client: SOCKS on 127.0.0.1:port.
    static func naiveConfig(_ s: Server, port: Int) -> String {
        let scheme = s.param("quic") == "1" ? "quic" : "https"
        let host = s.server.contains(":") ? "[\(s.server)]" : s.server
        func esc(_ v: String) -> String { v.addingPercentEncoding(withAllowedCharacters: .urlUserAllowed) ?? v }
        let auth = s.userId.isEmpty && s.password.isEmpty ? "" : "\(esc(s.userId)):\(esc(s.password))@"
        return json(["listen": "socks://127.0.0.1:\(port)", "proxy": "\(scheme)://\(auth)\(host):\(s.port)", "log": ""])
    }

    /// tor arguments for the Tor Expert Bundle on macOS: its own transport plugins (lyrebird, snowflake-client)
    /// instead of the in-process ones of iOS. `pt` = the bundle's pluggable_transports folder.
    static func torArgumentsMac(socksPort: Int, dataDir: String, logFile: String, bridges: [String], pt: String, geoip: String?) -> [String] {
        var a = ["--SocksPort", "127.0.0.1:\(socksPort)", "--DataDirectory", dataDir,
                 "--ClientOnly", "1", "--AvoidDiskWrites", "1", "--Log", "notice file \(logFile)", "--Log", "notice stdout"]
        if let g = geoip { a += ["--GeoIPFile", g + "/geoip", "--GeoIPv6File", g + "/geoip6"] }
        if !bridges.isEmpty {
            a += ["--UseBridges", "1"]
            let used = Set(bridges.map(bridgeTransport).filter { !$0.isEmpty })
            let lyrebird = ["obfs4", "meek_lite", "webtunnel", "scramblesuit", "obfs3"].filter(used.contains)
            if !lyrebird.isEmpty { a += ["--ClientTransportPlugin", "\(lyrebird.joined(separator: ",")) exec \(pt)/lyrebird"] }
            if used.contains("snowflake") { a += ["--ClientTransportPlugin", "snowflake exec \(pt)/snowflake-client"] }
            if used.contains("conjure") { a += ["--ClientTransportPlugin", "conjure exec \(pt)/conjure-client"] }
            for b in bridges { a += ["--Bridge", b] }
        }
        return a
    }
}
