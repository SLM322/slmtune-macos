import Foundation

/// The sing-box config for one connection — the iOS counterpart of SingBoxConfig.Build (Windows) and
/// ConfigBuilder.kt (Android). Order of the route rules matters: blocking first, then the user's own rules,
/// AI and calls, then the preset.
///
/// macOS: sing-box runs as a process. In TUN mode the helper starts it as root; otherwise it only offers the
/// local mixed proxy (and the app may point the system proxy at it). Rules by program (process_name) work in TUN.
enum ConfigBuilder {
    /// What the Mac adds to a connection.
    struct Mac {
        var tun = false
        /// Local port of tpws (Zapret): the listed sites go through it instead of "direct".
        var zapretPort: Int? = nil
        /// Program names that must never loop back into the tunnel (our own cores).
        var ownProcesses: [String] = []
        /// Log file (the helper replaces it with its own path when it runs sing-box as root).
        var logFile: String? = nil
        /// Zapret only: no VPN server, everything direct except the Zapret sites.
        var zapretOnly = false
    }
    static let lanRanges = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "224.0.0.0/4", "255.255.255.255/32"]

    /// "https://1.1.1.1/dns-query" → a sing-box 1.12+ DNS server object.
    static func dnsServer(tag: String, url: String, detour: String?) -> JSON {
        var o: JSON = ["tag": tag]
        let u = URLComponents(string: url)
        switch u?.scheme?.lowercased() {
        case "https":
            o["type"] = "https"; o["server"] = u?.host ?? "1.1.1.1"
            if let p = u?.path, !p.isEmpty, p != "/dns-query" { o["path"] = p }
        case "tls":
            o["type"] = "tls"; o["server"] = u?.host ?? "1.1.1.1"
        case "quic":
            o["type"] = "quic"; o["server"] = u?.host ?? "1.1.1.1"
        default:
            o["type"] = "udp"
            let raw = url.components(separatedBy: "://").last ?? ""
            o["server"] = raw.isEmpty ? "1.1.1.1" : raw
        }
        if let d = detour { o["detour"] = d }
        return o
    }

    private static func uniq(_ a: [String]) -> [String] {
        var seen = Set<String>()
        return a.filter { seen.insert($0).inserted }
    }

    private static func cidr(_ ip: String) -> String {
        if ip.contains("/") { return ip }
        return ip.contains(":") ? "\(ip)/128" : "\(ip)/32"
    }

    /// `backends`: server id → SOCKS port of its extra core, started by the extension before sing-box.
    static func build(_ s: AppSettings, server: Server, backends: [String: Int] = [:], mac: Mac = Mac()) throws -> String {
        let chain = mac.zapretOnly ? Outbounds.Built() : try Outbounds.chain(s, server, backends: backends)
        let udp = mac.zapretOnly || (ShareLinks.hasUdp(server) && Outbounds.hops(s, server).allSatisfy(ShareLinks.hasUdp))
        let selective = s.preset == .blocked

        // ---- rule sets (local files the app keeps up to date) ----
        var ruleSets: [JSON] = []
        func local(_ tag: String, _ url: URL, binary: Bool) {
            ruleSets.append(["type": "local", "tag": tag, "format": binary ? "binary" : "source", "path": url.path])
        }
        let blockTags: [String] = Lists.blocks.filter { s.blockLists.contains($0.id) && Lists.has(Lists.blockFile($0)) }.map {
            let tag = "block-\($0.id)"
            local(tag, Lists.blockFile($0), binary: true)
            return tag
        }
        let presetTags = Lists.presetLists(s.preset).filter { Lists.has(Lists.ruleFile($0)) }
        for t in presetTags { local(t, Lists.ruleFile(t), binary: false) }

        // ---- services ----
        let on = { (d: ServiceDef) in !s.disabledServices.contains(d.id) }
        let aiDomains = uniq(Catalog.inGroup(.ai).filter(on).flatMap(\.domains) + Catalog.aiAlways)
        let callDefs = Catalog.inGroup(.call).filter(on)
        let callDomains = uniq(callDefs.flatMap(\.domains))
        let telegramOn = callDefs.contains { $0.id == "telegram" }

        var rules: [JSON] = [
            ["action": "sniff"],
            ["protocol": "dns", "action": "hijack-dns"],
        ]
        // Our own cores (they reach the servers) must never loop back into the tunnel.
        if mac.tun, !mac.ownProcesses.isEmpty { rules.append(["process_name": mac.ownProcesses, "action": "route", "outbound": "direct"]) }
        rules.append(["ip_is_private": true, "action": "route", "outbound": "direct"])
        if !blockTags.isEmpty { rules.append(["rule_set": blockTags, "action": "reject"]) }
        let proxyTag = mac.zapretOnly ? "direct" : "proxy"
        // Programs (TUN only: sing-box finds the process of each connection).
        if mac.tun {
            for r in s.appRules where r.enabled && !r.process.trimmingCharacters(in: .whitespaces).isEmpty {
                var o: JSON = ["process_name": [r.process.trimmingCharacters(in: .whitespaces)]]
                if r.action == "block" { o["action"] = "reject" }
                else { o["action"] = "route"; o["outbound"] = r.action == "vpn" ? proxyTag : "direct" }
                rules.append(o)
            }
        }
        // Kill switch for selected sites: while connected they always go through the VPN.
        if s.killSwitch, s.killSwitchScope == "selected", !mac.zapretOnly {
            let d = uniq(s.killSwitchSites.map { $0.trimmingCharacters(in: .whitespaces).lowercased() }.filter { !$0.isEmpty && !MacRules.isAddress($0) })
            let ips = s.killSwitchSites.map { $0.trimmingCharacters(in: .whitespaces) }.filter(MacRules.isAddress).map(cidr)
            if !d.isEmpty { rules.append(["domain_suffix": d, "action": "route", "outbound": "proxy"]) }
            if !ips.isEmpty { rules.append(["ip_cidr": uniq(ips), "action": "route", "outbound": "proxy"]) }
        }
        // Zapret: the listed sites go through tpws (DPI bypass) instead of the VPN or direct.
        if mac.zapretPort != nil {
            let z = uniq(s.zapretSites.map(MacRules.clean).filter { !$0.isEmpty })
            if !z.isEmpty { rules.append(["domain_suffix": z, "network": ["tcp"], "action": "route", "outbound": "zapret"]) }
        }
        // The user's own rules win over everything below.
        for r in s.customRules where r.enabled {
            func target(_ o: JSON) -> JSON {
                var o = o
                if r.action == "block" { o["action"] = "reject" }
                else { o["action"] = "route"; o["outbound"] = r.action == "direct" ? "direct" : "proxy" }
                return o
            }
            let domains = r.domains.map { $0.trimmingCharacters(in: .whitespaces).lowercased() }
                .map { $0.hasPrefix("*.") ? String($0.dropFirst(2)) : $0 }.filter { !$0.isEmpty }
            if !domains.isEmpty { rules.append(target(["domain_suffix": uniq(domains)])) }
            let ips = r.ips.map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }.map(cidr)
            if !ips.isEmpty { rules.append(target(["ip_cidr": uniq(ips)])) }
        }
        // A server without UDP: QUIC is refused at once so browsers fall back to TCP instead of leaking.
        if !udp { rules.append(["network": ["udp"], "port": [443], "action": "reject"]) }
        if s.aiViaVpn, !aiDomains.isEmpty, !mac.zapretOnly {
            var r: JSON = ["domain_suffix": aiDomains, "action": "route", "outbound": "proxy"]
            if !udp { r["network"] = ["tcp"] }
            rules.append(r)
            let aiProcs = MacRules.processes(s, group: "ai")
            if mac.tun, !aiProcs.isEmpty {
                var p: JSON = ["process_name": aiProcs, "action": "route", "outbound": "proxy"]
                if !udp { p["network"] = ["tcp"] }
                rules.append(p)
            }
            let own = MacRules.ownDomains(s, group: "ai")
            if !own.isEmpty { rules.append(["domain_suffix": own, "action": "route", "outbound": "proxy"]) }
            let ownIps = MacRules.ownIps(s, group: "ai").map(cidr)
            if !ownIps.isEmpty { rules.append(["ip_cidr": uniq(ownIps), "action": "route", "outbound": "proxy"]) }
        }
        // Games (TUN): their programs direct for a lower ping; with "games via VPN" their UDP goes through the VPN.
        if mac.tun, s.gameMode {
            let games = MacRules.processes(s, group: "game")
            if !games.isEmpty {
                if s.gamesViaVpn, udp, !mac.zapretOnly {
                    rules.append(["process_name": games, "network": ["udp"], "action": "route", "outbound": "proxy"])
                }
                rules.append(["process_name": games, "action": "route", "outbound": "direct"])
            }
        }
        let gameSites = MacRules.ownDomains(s, group: "game")
        if !gameSites.isEmpty, !mac.zapretOnly { rules.append(["domain_suffix": gameSites, "action": "route", "outbound": "proxy"]) }
        // Messengers and calls: their sites (and Telegram's data centres) through the VPN.
        if s.callsViaVpn, !mac.zapretOnly {
            let callProcs = MacRules.processes(s, group: "call")
            if mac.tun, udp, !callProcs.isEmpty {
                rules.append(["process_name": callProcs, "network": ["udp"], "action": "route", "outbound": "proxy"])
            }
            if !callDomains.isEmpty { rules.append(["domain_suffix": callDomains, "action": "route", "outbound": "proxy"]) }
            if telegramOn {
                let nets = s.ipv6 ? Catalog.telegramCidrs : Catalog.telegramCidrs.filter { !$0.contains(":") }
                rules.append(["ip_cidr": nets, "action": "route", "outbound": "proxy"])
            }
        }
        if !udp { rules.append(["network": ["udp"], "action": "route", "outbound": "direct"]) }
        if !presetTags.isEmpty, !mac.zapretOnly {
            rules.append(["rule_set": presetTags, "action": "route", "outbound": selective ? "proxy" : "direct"])
        }

        // ---- DNS: direct names via a DoH reachable without the VPN, the rest through the tunnel ----
        var dnsRules: [JSON] = []
        if !blockTags.isEmpty { dnsRules.append(["rule_set": blockTags, "action": "predefined", "rcode": "NXDOMAIN"]) }
        if s.aiViaVpn { dnsRules.append(["domain_suffix": aiDomains, "action": "route", "server": "remote-dns"]) }
        let domainSets = presetTags.filter { $0 != Lists.ruIps }
        if !domainSets.isEmpty {
            dnsRules.append(["rule_set": domainSets, "action": "route", "server": selective ? "remote-dns" : "direct-dns"])
        }
        var dns: JSON = [
            "servers": [dnsServer(tag: "remote-dns", url: s.remoteDns, detour: mac.zapretOnly ? nil : "proxy"),
                        dnsServer(tag: "direct-dns", url: s.directDns, detour: nil)],
            "rules": mac.zapretOnly ? dnsRules.filter { $0["rcode"] != nil } : dnsRules,
            "final": selective || mac.zapretOnly ? "direct-dns" : "remote-dns",
        ]
        if !s.ipv6 { dns["strategy"] = "ipv4_only" }

        // ---- TUN: libbox turns it into NEPacketTunnelNetworkSettings (see ExtensionPlatformInterface.openTun) ----
        var tun: JSON = [
            "type": "tun", "tag": "tun-in",
            "address": s.ipv6 ? ["172.19.0.1/30", "fdfe:dcba:9876::1/126"] : ["172.19.0.1/30"],
            "mtu": s.mtu, "auto_route": true, "strict_route": true,
            // gVisor for UDP, the system stack for TCP: lighter on the extension's ~50 MB memory limit.
            "stack": "mixed",
        ]
        // Local network (router, printers, AirPlay) stays outside the tunnel.
        if s.lanBypass, !s.killSwitch { tun["route_exclude_address"] = lanRanges }

        var outbounds = chain.outbounds
        outbounds.append(["type": "direct", "tag": "direct"])
        if let zp = mac.zapretPort {
            outbounds.append(["type": "socks", "tag": "zapret", "server": "127.0.0.1", "server_port": zp, "version": "5"])
        }
        var route: JSON = [
            "rules": rules,
            "final": selective || mac.zapretOnly ? "direct" : "proxy",
            "auto_detect_interface": true,
            "default_domain_resolver": "direct-dns",
        ]
        if mac.tun { route["find_process"] = true }
        if !ruleSets.isEmpty { route["rule_set"] = ruleSets }

        // The local proxy: always there (browsers through the system proxy, other programs by hand).
        let mixed: JSON = ["type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "listen_port": s.mixedPort]
        var config: JSON = [
            "log": ["level": s.logLevel, "timestamp": true, "output": mac.logFile ?? SharedLog.singBoxLogFile.path] as JSON,
            "dns": dns,
            "inbounds": mac.tun ? [tun, mixed] : [mixed],
            "outbounds": outbounds,
            "route": route,
            "experimental": [
                "cache_file": ["enabled": true] as JSON,
                // Connections panel in the app; loopback only, with a secret.
                "clash_api": ["external_controller": "127.0.0.1:\(AppGroup.clashPort)", "secret": AppGroup.clashSecret] as JSON,
            ] as JSON,
        ]
        if !chain.endpoints.isEmpty { config["endpoints"] = chain.endpoints }
        let data = try JSONSerialization.data(withJSONObject: config, options: [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes])
        return String(decoding: data, as: UTF8.self)
    }
}
