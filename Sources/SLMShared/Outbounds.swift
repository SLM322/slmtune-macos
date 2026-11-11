import Foundation

typealias JSON = [String: Any]

/// Servers → sing-box outbounds (port of ShareLinks.BuildSingBoxOutbound + ApplyProtocolSettings from the
/// Windows version and Outbounds.kt from Android). The result is a set: the outbound tagged `tag` plus the
/// helpers it needs (ShadowTLS layer, cascade hops, group members); WireGuard goes in as an endpoint.
enum Outbounds {
    final class Built {
        var outbounds: [JSON] = []
        var endpoints: [JSON] = []
        /// Server id → local SOCKS port of its extra core (Xray, mihomo, TrustTunnel, Tor); see Engines.
        var backends: [String: Int] = [:]
        init(backends: [String: Int] = [:]) { self.backends = backends }
    }

    private static func truthy(_ v: String) -> Bool { v == "1" || v.lowercased() == "true" }
    static func csv(_ v: String) -> [String] {
        v.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }
    }

    static func tls(_ s: Server, force: Bool) -> JSON? {
        let sec = s.param("security").lowercased()
        if !force, !["tls", "reality", "xtls"].contains(sec) { return nil }
        let sni = s.param("sni", s.param("peer", s.param("host")))
        let fp = s.param("fp")
        var t: JSON = ["enabled": true]
        if !sni.isEmpty { t["server_name"] = sni }
        let pinned = s.param("cert")
        if !pinned.isEmpty { t["certificate"] = pinned }
        else if truthy(s.param("allowInsecure")) || truthy(s.param("insecure")) || truthy(s.param("allow_insecure")) { t["insecure"] = true }
        let alpn = s.param("alpn")
        if !alpn.isEmpty { t["alpn"] = csv(alpn) } else if s.kind == "tuic" { t["alpn"] = ["h3"] }
        if sec == "reality" || !fp.isEmpty { t["utls"] = ["enabled": true, "fingerprint": fp.isEmpty ? "chrome" : fp] as JSON }
        if sec == "reality" { t["reality"] = ["enabled": true, "public_key": s.param("pbk"), "short_id": s.param("sid")] as JSON }
        return t
    }

    static func transport(_ s: Server) -> JSON? {
        let host = s.param("host"), path = s.param("path")
        switch s.param("type", "tcp").lowercased() {
        case "ws":
            return ["type": "ws", "path": path.isEmpty ? "/" : path, "headers": (host.isEmpty ? [:] : ["Host": host]) as [String: String]]
        case "grpc":
            return ["type": "grpc", "service_name": s.param("serviceName", path)]
        case "http", "h2":
            return ["type": "http", "path": path.isEmpty ? "/" : path, "host": csv(host)]
        case "httpupgrade":
            return ["type": "httpupgrade", "path": path.isEmpty ? "/" : path, "host": host]
        default:
            return nil
        }
    }

    /// One server; `tag` is what routing points at.
    static func build(_ s: Server, tag: String, into: Built, all: [Server], ps: ProtocolSettings) throws {
        if let port = into.backends[s.id] {
            into.outbounds.append(["type": "socks", "tag": tag, "server": "127.0.0.1", "server_port": port, "version": "5"])
            return
        }
        if let e = Engines.engine(s) {
            throw LinkError(L("«%@» работает через %@, а это ядро не запущено.", s.title, e.title))
        }
        switch s.kind {
        case "group":
            // Members first, then a urltest over them. "fallback" keeps the chosen one until it fails.
            let members = s.members.compactMap { id in all.first { $0.id == id && $0.kind != "group" } }
            guard !members.isEmpty else { throw LinkError(L("В группе нет серверов.")) }
            var tags: [String] = []
            for (i, m) in members.enumerated() {
                let t = "\(tag)-m\(i)"
                try build(m, tag: t, into: into, all: all, ps: ps)
                tags.append(t)
            }
            into.outbounds.append([
                "type": "urltest", "tag": tag, "outbounds": tags,
                "url": "https://www.gstatic.com/generate_204", "interval": "2m",
                "tolerance": s.param("mode") == "fallback" ? 5000 : 80,
            ])
            return
        case "wireguard":
            into.endpoints.append(wireguard(s, tag: tag))
            return
        default: break
        }

        var o: JSON = ["tag": tag, "server": s.server, "server_port": s.port]
        var withTransport = false
        switch s.kind {
        case "socks":
            o["type"] = "socks"; o["version"] = "5"
            if !s.userId.isEmpty { o["username"] = s.userId; o["password"] = s.password }
        case "hysteria":
            o["type"] = "hysteria"
            o["up_mbps"] = Int(s.param("upmbps")).flatMap { $0 > 0 ? $0 : nil } ?? 20
            o["down_mbps"] = Int(s.param("downmbps")).flatMap { $0 > 0 ? $0 : nil } ?? 100
            if !s.password.isEmpty { o["auth_str"] = s.password }
            if !s.param("obfsParam").isEmpty { o["obfs"] = s.param("obfsParam") }
            o["tls"] = tls(s, force: true)
        case "vless":
            if ShareLinks.needsXray(s.params) {
                throw LinkError(L("VLESS XHTTP и VLESS Encryption требуют Xray — на iOS его нет, только в версии для Windows и Android."))
            }
            o["type"] = "vless"; o["uuid"] = s.userId
            if !s.param("flow").isEmpty { o["flow"] = s.param("flow") }
            o["packet_encoding"] = "xudp"
            withTransport = true
        case "vmess":
            o["type"] = "vmess"; o["uuid"] = s.userId; o["security"] = s.param("scy", "auto")
            o["alter_id"] = Int(s.param("aid")) ?? 0
            withTransport = true
        case "trojan":
            o["type"] = "trojan"; o["password"] = s.password
            withTransport = true
        case "ss":
            o["type"] = "shadowsocks"; o["method"] = s.userId; o["password"] = s.password
            let plugin = s.param("plugin")
            if plugin.lowercased().hasPrefix("shadow-tls") {
                // ShadowTLS v3: the TLS layer is its own outbound, Shadowsocks goes through it.
                var opts: [String: String] = [:]
                for kv in plugin.split(separator: ";").dropFirst() {
                    let p = kv.split(separator: "=", maxSplits: 1).map { $0.trimmingCharacters(in: .whitespaces) }
                    if p.count == 2 { opts[p[0]] = p[1] }
                }
                let stls = "\(tag)-stls"
                into.outbounds.append([
                    "type": "shadowtls", "tag": stls, "server": s.server, "server_port": s.port,
                    "version": Int(opts["version"] ?? "") ?? 3, "password": opts["password"] ?? "",
                    "tls": ["enabled": true, "server_name": opts["host"] ?? "www.microsoft.com",
                            "utls": ["enabled": true, "fingerprint": "chrome"] as JSON] as JSON,
                ])
                o.removeValue(forKey: "server"); o.removeValue(forKey: "server_port")
                o["detour"] = stls
            } else if !plugin.isEmpty {
                if let semi = plugin.firstIndex(of: ";") {
                    o["plugin"] = String(plugin[..<semi]); o["plugin_opts"] = String(plugin[plugin.index(after: semi)...])
                } else { o["plugin"] = plugin }
            }
        case "hysteria2":
            o["type"] = "hysteria2"; o["password"] = s.password
            let obfs = s.param("obfs")
            if !obfs.isEmpty { o["obfs"] = ["type": obfs, "password": s.param("obfs-password")] }
            let hop = s.param("mport", s.param("ports"))
            if !hop.isEmpty { o.removeValue(forKey: "server_port"); o["server_ports"] = csv(hop.replacingOccurrences(of: "-", with: ":")) }
            o["tls"] = tls(s, force: true)
        case "tuic":
            o["type"] = "tuic"; o["uuid"] = s.userId; o["password"] = s.password
            o["congestion_control"] = s.param("congestion_control", "bbr")
            o["tls"] = tls(s, force: true)
        case "anytls":
            o["type"] = "anytls"; o["password"] = s.password
            o["tls"] = tls(s, force: true)
        case "naive":
            // Needs libbox built with with_naive_outbound (the default in build_libbox for Apple).
            o["type"] = "naive"; o["username"] = s.userId; o["password"] = s.password
            if s.param("quic") == "1" { o["quic"] = true }
            o["tls"] = ["enabled": true, "server_name": s.param("sni", s.server)] as JSON
        default:
            throw LinkError(L("Протокол %@ не поддерживается на iOS.", s.kind))
        }
        if withTransport {
            if let t = tls(s, force: false) { o["tls"] = t }
            if let t = transport(s) { o["transport"] = t }
        }
        applyProtocolSettings(&o, s, ps)
        into.outbounds.append(o)
    }

    /// Settings → Протоколы, as ApplyProtocolSettings in the Windows version.
    static func applyProtocolSettings(_ o: inout JSON, _ s: Server, _ ps: ProtocolSettings) {
        if var t = o["tls"] as? JSON {
            let reality = t["reality"] != nil
            if !ps.fingerprintOverride.isEmpty, !["naive", "hysteria2", "tuic", "hysteria"].contains(s.kind) {
                t["utls"] = ["enabled": true, "fingerprint": ps.fingerprintOverride] as JSON
            }
            // Fragmenting the ClientHello defeats SNI-based DPI; not for Reality or QUIC protocols.
            if ["vless", "vmess", "trojan", "anytls"].contains(s.kind), !reality {
                if ps.tlsFragment { t["fragment"] = true }
                if ps.tlsRecordFragment { t["record_fragment"] = true }
            }
            o["tls"] = t
        }
        let muxable = ["vmess", "trojan", "ss"].contains(s.kind) || (s.kind == "vless" && s.param("flow").isEmpty)
        if muxable, ["smux", "yamux", "h2mux"].contains(ps.multiplex), o["detour"] == nil {
            o["multiplex"] = ["enabled": true, "protocol": ps.multiplex,
                              "max_connections": min(max(ps.multiplexMaxConnections, 1), 32), "padding": ps.multiplexPadding] as JSON
        }
        switch s.kind {
        case "hysteria2", "hysteria":
            if ps.hysteriaUpMbps > 0 { o["up_mbps"] = ps.hysteriaUpMbps }
            if ps.hysteriaDownMbps > 0 { o["down_mbps"] = ps.hysteriaDownMbps }
        case "tuic":
            if !ps.tuicCongestion.isEmpty { o["congestion_control"] = ps.tuicCongestion }
            if ps.tuicZeroRtt { o["zero_rtt_handshake"] = true }
        case "ss":
            if ps.shadowsocksUdpOverTcp, o["plugin"] == nil, o["detour"] == nil { o["udp_over_tcp"] = true }
        default: break
        }
    }

    /// WireGuard / WARP as a sing-box endpoint (1.11+).
    static func wireguard(_ s: Server, tag: String) -> JSON {
        var peer: JSON = [
            "address": s.server, "port": s.port, "public_key": s.param("publickey"),
            "allowed_ips": csv(s.param("allowedips", "0.0.0.0/0, ::/0")),
            "persistent_keepalive_interval": Int(s.param("keepalive")) ?? 25,
        ]
        if !s.param("presharedkey").isEmpty { peer["pre_shared_key"] = s.param("presharedkey") }
        let reserved = csv(s.param("reserved")).compactMap { Int($0) }
        if reserved.count == 3 { peer["reserved"] = reserved }
        return [
            "type": "wireguard", "tag": tag, "mtu": Int(s.param("mtu")) ?? 1280,
            "address": csv(s.param("address")), "private_key": s.password, "peers": [peer],
        ]
    }

    /// The cascade for `s`: its own "через" hops (each may have its own), or the global entry.
    /// Entry first. Loops and missing servers end the chain; at most 4 hops.
    static func hops(_ settings: AppSettings, _ s: Server) -> [Server] {
        var chain: [Server] = []
        var seen: Set<String> = [s.id]
        var cur = s
        while chain.count < 4 {
            var via = cur.viaId
            if via.isEmpty, cur.id == s.id { via = settings.cascadeEntryId }
            guard !via.isEmpty, seen.insert(via).inserted, let relay = settings.server(via) else { break }
            chain.insert(relay, at: 0)
            cur = relay
        }
        return chain
    }

    /// The active server with its cascade: hop0 → hop1 → … → "proxy". Each hop reaches the next through the
    /// previous one (detour), so the exit server sees only the previous hop's address.
    static func chain(_ settings: AppSettings, _ s: Server, backends: [String: Int] = [:]) throws -> Built {
        let built = Built(backends: backends)
        let hs = hops(settings, s)
        // An extra core dials its server itself, so it can't go through another hop: only the first one.
        if let late = (hs.dropFirst() + (hs.isEmpty ? [] : [s])).first(where: { Engines.engine($0) != nil }) {
            throw LinkError(L("«%@» работает через отдельное ядро и в каскаде может быть только первым.", late.title))
        }
        for (i, h) in hs.enumerated() { try build(h, tag: "hop\(i)", into: built, all: settings.servers, ps: settings.protocols) }
        try build(s, tag: "proxy", into: built, all: settings.servers, ps: settings.protocols)
        if !hs.isEmpty {
            for i in 1...hs.count {
                let tag = i == hs.count ? "proxy" : "hop\(i)"
                let prev = "hop\(i - 1)"
                attach(built, tag: tag, via: prev)
            }
        }
        return built
    }

    /// Makes `tag` dial through `via`. A group passes it on to its members; Shadowsocks over ShadowTLS
    /// to its TLS layer (the one that actually opens the connection).
    private static func attach(_ built: Built, tag: String, via: String) {
        if let k = built.outbounds.firstIndex(where: { $0["tag"] as? String == tag }) {
            let o = built.outbounds[k]
            if o["server"] as? String == "127.0.0.1", o["type"] as? String == "socks" {
                return // an extra core: it dials the server itself
            } else if o["type"] as? String == "urltest" {
                for m in (o["outbounds"] as? [String]) ?? [] { attach(built, tag: m, via: via) }
            } else if let inner = o["detour"] as? String {
                attach(built, tag: inner, via: via)
            } else {
                built.outbounds[k]["detour"] = via
                built.outbounds[k].removeValue(forKey: "multiplex")
            }
        } else if let k = built.endpoints.firstIndex(where: { $0["tag"] as? String == tag }) {
            built.endpoints[k]["detour"] = via
        }
    }
}
