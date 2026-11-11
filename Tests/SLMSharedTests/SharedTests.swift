import XCTest
#if canImport(SLMShared)
@testable import SLMShared // SwiftPM on Linux (scripts/linux-check.sh); in Xcode the sources are compiled in
#endif

/// Logic tests for the code shared by the app and the extension: share links → servers → sing-box config.
/// Run on a Mac: `xcodebuild test -scheme SLMtune -destination 'platform=iOS Simulator,name=iPhone 15'`.
final class ShareLinksTests: XCTestCase {
    func testVlessReality() throws {
        let s = try ShareLinks.parse("vless://11111111-2222-3333-4444-555555555555@example.com:443?type=tcp&security=reality&pbk=PUBKEY&sid=ab12&sni=www.microsoft.com&fp=chrome&flow=xtls-rprx-vision#My%20server")
        XCTAssertEqual(s.kind, "vless")
        XCTAssertEqual(s.server, "example.com")
        XCTAssertEqual(s.port, 443)
        XCTAssertEqual(s.name, "My server")
        XCTAssertEqual(s.param("pbk"), "PUBKEY")
        let b = Outbounds.Built()
        try Outbounds.build(s, tag: "proxy", into: b, all: [s], ps: ProtocolSettings())
        let o = b.outbounds[0]
        XCTAssertEqual(o["type"] as? String, "vless")
        XCTAssertEqual(o["flow"] as? String, "xtls-rprx-vision")
        let tls = o["tls"] as? JSON
        XCTAssertEqual((tls?["reality"] as? JSON)?["public_key"] as? String, "PUBKEY")
        XCTAssertEqual(tls?["server_name"] as? String, "www.microsoft.com")
    }

    func testVlessXhttpGoesToXray() throws {
        let s = try ShareLinks.parse("vless://11111111-2222-3333-4444-555555555555@h.com:443?type=xhttp&security=tls&path=/x&mode=auto")
        XCTAssertEqual(Engines.engine(s), .xray)
        // Without a running core the outbound can't be built…
        XCTAssertThrowsError(try Outbounds.build(s, tag: "proxy", into: Outbounds.Built(), all: [s], ps: ProtocolSettings()))
        // …with one it is a socks hop to the local port.
        let b = Outbounds.Built(backends: [s.id: 20001])
        try Outbounds.build(s, tag: "proxy", into: b, all: [s], ps: ProtocolSettings())
        XCTAssertEqual(b.outbounds[0]["type"] as? String, "socks")
        XCTAssertEqual(b.outbounds[0]["server_port"] as? Int, 20001)
        let x = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(Engines.xrayConfig(s, port: 20001, logLevel: "warn").utf8)) as? JSON)
        let stream = (x["outbounds"] as? [JSON])?.first?["streamSettings"] as? JSON
        XCTAssertEqual(stream?["network"] as? String, "xhttp")
    }

    func testTrustTunnelRoundTrip() throws {
        var s = Server(name: "tt test", kind: "tt", server: "vpn.example.com", port: 443, userId: "user", password: "p@ss",
                       params: ["addresses": "1.2.3.4:443", "upstream": "http3", "sni": "cdn.example.com"])
        s.link = MoreLinks.ttLink(s)
        let back = try ShareLinks.parse(s.link)
        XCTAssertEqual(back.kind, "tt")
        XCTAssertEqual(back.server, "vpn.example.com")
        XCTAssertEqual(back.userId, "user")
        XCTAssertEqual(back.password, "p@ss")
        XCTAssertEqual(back.param("upstream"), "http3")
        XCTAssertEqual(back.param("addresses"), "1.2.3.4:443")
        XCTAssertTrue(Engines.ttConfig(back, port: 20002).contains("[listener.socks]\naddress = \"127.0.0.1:20002\""))
    }

    func testAmneziaWireGuardGoesToMihomo() throws {
        let s = try ShareLinks.parse("wireguard://cHJpdmF0ZWtleXByaXZhdGVrZXlwcml2YXRla2V5MTI%3D@1.2.3.4:51820?publickey=cHVibGlja2V5cHVibGlja2V5cHVibGlja2V5cHViMTI%3D&address=10.8.0.2/32&jc=4&jmin=40&jmax=70&h1=1#awg")
        XCTAssertEqual(s.kind, "amneziawg")
        XCTAssertEqual(Engines.engine(s), .mihomo)
        let cfg = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(Engines.mihomoConfig([(s, 20003)], logLevel: "warn").utf8)) as? JSON)
        let p = try XCTUnwrap((cfg["proxies"] as? [JSON])?.first)
        XCTAssertEqual(p["type"] as? String, "wireguard")
        XCTAssertEqual((p["amnezia-wg-option"] as? JSON)?["jc"] as? Int, 4)
        XCTAssertEqual(((cfg["listeners"] as? [JSON])?.first)?["port"] as? Int, 20003)
    }

    func testMieruAndSsr() throws {
        let m = try ShareLinks.parse("mierus://alice:secret@m.example.com?port=8964&protocol=TCP#m")
        XCTAssertEqual(m.kind, "mieru")
        XCTAssertEqual(m.port, 8964)
        XCTAssertEqual(m.password, "secret")
        let body = "1.2.3.4:8388:origin:aes-256-cfb:plain:" + Data("pw".utf8).base64EncodedString() + "/?remarks=" + Data("ssr test".utf8).base64EncodedString()
        let r = try ShareLinks.parse("ssr://" + Data(body.utf8).base64EncodedString())
        XCTAssertEqual(r.kind, "ssr")
        XCTAssertEqual(r.password, "pw")
        XCTAssertEqual(r.name, "ssr test")
    }

    func testTorArguments() {
        let a = Engines.torArguments(socksPort: 9050, dataDir: "/d", logFile: "/l", bridges: ["obfs4 1.2.3.4:443 FP cert=x iat-mode=0"],
                                     transportPorts: ["obfs4": 30000])
        XCTAssertTrue(a.contains("obfs4 socks5 127.0.0.1:30000"))
        XCTAssertEqual(Engines.bridgeTransport("obfs4 1.2.3.4:443 FP"), "obfs4")
        XCTAssertEqual(Engines.bridgeTransport("1.2.3.4:443 FP"), "")
    }

    func testShadowsocksSip002() throws {
        let ui = Data("2022-blake3-aes-128-gcm:c2VjcmV0c2VjcmV0MTI=".utf8).base64EncodedString()
        let s = try ShareLinks.parse("ss://\(ui)@1.2.3.4:8388#ss2022")
        XCTAssertEqual(s.kind, "ss")
        XCTAssertEqual(s.userId, "2022-blake3-aes-128-gcm")
        XCTAssertEqual(s.password, "c2VjcmV0c2VjcmV0MTI=")
        XCTAssertEqual(s.port, 8388)
    }

    func testHysteria2PortHopping() throws {
        let s = try ShareLinks.parse("hy2://pass@hy.example.com:443?sni=hy.example.com&obfs=salamander&obfs-password=x&mport=20000-30000#hy")
        XCTAssertEqual(s.kind, "hysteria2")
        XCTAssertEqual(s.password, "pass")
        let b = Outbounds.Built()
        try Outbounds.build(s, tag: "proxy", into: b, all: [s], ps: ProtocolSettings())
        XCTAssertEqual(b.outbounds[0]["server_ports"] as? [String], ["20000:30000"])
        XCTAssertNil(b.outbounds[0]["server_port"])
    }

    func testTuic() throws {
        let s = try ShareLinks.parse("tuic://11111111-2222-3333-4444-555555555555:pw@[2001:db8::1]:8443?congestion_control=bbr&alpn=h3#t")
        XCTAssertEqual(s.server, "2001:db8::1")
        XCTAssertEqual(s.port, 8443)
        XCTAssertEqual(s.password, "pw")
    }

    func testVmessBase64() throws {
        let js = #"{"v":"2","ps":"vm","add":"v.example.com","port":"443","id":"11111111-2222-3333-4444-555555555555","net":"ws","path":"/ws","host":"cdn.example.com","tls":"tls"}"#
        let s = try ShareLinks.parse("vmess://" + Data(js.utf8).base64EncodedString())
        XCTAssertEqual(s.kind, "vmess")
        XCTAssertEqual(s.param("type"), "ws")
        let b = Outbounds.Built()
        try Outbounds.build(s, tag: "proxy", into: b, all: [s], ps: ProtocolSettings())
        XCTAssertEqual((b.outbounds[0]["transport"] as? JSON)?["path"] as? String, "/ws")
    }

    func testWireGuardConf() throws {
        let conf = """
        [Interface]
        PrivateKey = cHJpdmF0ZWtleXByaXZhdGVrZXlwcml2YXRla2V5MTI=
        Address = 10.0.0.2/32
        [Peer]
        PublicKey = cHVibGlja2V5cHVibGlja2V5cHVibGlja2V5cHViMTI=
        Endpoint = wg.example.com:51820
        AllowedIPs = 0.0.0.0/0
        """
        let s = try XCTUnwrap(ShareLinks.parseWireGuardConf(conf))
        XCTAssertEqual(s.server, "wg.example.com")
        XCTAssertEqual(Outbounds.wireguard(s, tag: "proxy")["type"] as? String, "wireguard")
    }

    func testSubscriptionBase64Body() {
        let body = Data("trojan://p@a.com:443#a\nvless://11111111-2222-3333-4444-555555555555@b.com:443#b".utf8).base64EncodedString()
        XCTAssertEqual(ShareLinks.findLinks(body).count, 2)
    }

    func testUserInfo() {
        var sub = Subscription()
        Subscriptions_applyUserInfo(&sub, "upload=1073741824; download=2147483648; total=10737418240; expire=1767139200")
        XCTAssertEqual(sub.total, 10_737_418_240)
        XCTAssertEqual(sub.expire, 1_767_139_200)
    }

    /// Subscriptions lives in the app target; the header parser is re-stated here to keep tests app-free.
    private func Subscriptions_applyUserInfo(_ s: inout Subscription, _ header: String) {
        for part in header.split(separator: ";") {
            let kv = part.split(separator: "=", maxSplits: 1).map { $0.trimmingCharacters(in: .whitespaces) }
            guard kv.count == 2, let v = Double(kv[1]) else { continue }
            switch kv[0] { case "total": s.total = Int64(v); case "expire": s.expire = Int64(v); default: break }
        }
    }
}

final class ConfigBuilderTests: XCTestCase {
    private func settings() throws -> (AppSettings, Server) {
        var s = AppSettings()
        let a = try ShareLinks.parse("trojan://pw@entry.example.com:443?security=tls&sni=entry.example.com#entry")
        let b = try ShareLinks.parse("vless://11111111-2222-3333-4444-555555555555@exit.example.com:443?security=tls&type=ws&path=/x#exit")
        s.servers = [a, b]
        s.activeId = b.id
        return (s, b)
    }

    private func parse(_ json: String) throws -> JSON {
        try XCTUnwrap(JSONSerialization.jsonObject(with: Data(json.utf8)) as? JSON)
    }

    func testAiRulesAndFinal() throws {
        var (s, b) = try settings()
        s.preset = .all
        let cfg = try parse(try ConfigBuilder.build(s, server: b))
        let route = try XCTUnwrap(cfg["route"] as? JSON)
        XCTAssertEqual(route["final"] as? String, "proxy")
        let rules = try XCTUnwrap(route["rules"] as? [JSON])
        XCTAssertTrue(rules.contains { ($0["domain_suffix"] as? [String])?.contains("claude.ai") == true })
        // macOS without TUN: only the local mixed proxy.
        let inbounds = try XCTUnwrap(cfg["inbounds"] as? [JSON])
        XCTAssertEqual(inbounds.map { $0["type"] as? String }, ["mixed"])
        XCTAssertEqual(inbounds[0]["listen"] as? String, "127.0.0.1")
    }

    // MARK: macOS

    func testTunWithProgramRules() throws {
        var (s, b) = try settings()
        s.appRules = [AppRule(process: "Telegram", action: "vpn"), AppRule(process: "Zoom", action: "block")]
        s.gameMode = true
        s.gamesViaVpn = true
        s.ownServices = [OwnService(name: "мой ИИ", group: "ai", domains: ["https://www.my-ai.example/x"], ips: ["203.0.113.5"], processes: ["MyAI"])]
        let cfg = try parse(try ConfigBuilder.build(s, server: b, mac: .init(tun: true, ownProcesses: ["xray", "mihomo"])))
        let inbounds = try XCTUnwrap(cfg["inbounds"] as? [JSON])
        XCTAssertEqual(inbounds.map { $0["type"] as? String }, ["tun", "mixed"])
        let route = try XCTUnwrap(cfg["route"] as? JSON)
        XCTAssertEqual(route["find_process"] as? Bool, true)
        let rules = try XCTUnwrap(route["rules"] as? [JSON])
        func procRule(_ name: String) -> JSON? { rules.first { ($0["process_name"] as? [String])?.contains(name) == true } }
        // Our cores go direct before anything else can send them into the tunnel.
        let own = try XCTUnwrap(rules.firstIndex { ($0["process_name"] as? [String]) == ["xray", "mihomo"] })
        XCTAssertLessThan(own, try XCTUnwrap(rules.firstIndex { $0["ip_is_private"] != nil }))
        XCTAssertEqual(procRule("Telegram")?["outbound"] as? String, "proxy")
        XCTAssertEqual(procRule("Zoom")?["action"] as? String, "reject")
        XCTAssertEqual(procRule("Claude")?["outbound"] as? String, "proxy")
        XCTAssertNotNil(procRule("MyAI"))
        XCTAssertTrue(rules.contains { ($0["domain_suffix"] as? [String])?.contains("my-ai.example") == true })
        XCTAssertTrue(rules.contains { ($0["ip_cidr"] as? [String])?.contains("203.0.113.5/32") == true })
        // Games: UDP through the VPN first, the rest of the game direct.
        let steam = rules.filter { ($0["process_name"] as? [String])?.contains("steam_osx") == true }
        XCTAssertEqual(steam.map { $0["outbound"] as? String }, ["proxy", "direct"])
    }

    func testProgramRulesNeedTun() throws {
        var (s, b) = try settings()
        s.appRules = [AppRule(process: "Telegram", action: "vpn")]
        let cfg = try parse(try ConfigBuilder.build(s, server: b))
        let rules = try XCTUnwrap((cfg["route"] as? JSON)?["rules"] as? [JSON])
        XCTAssertFalse(rules.contains { $0["process_name"] != nil })
    }

    func testZapretOnlyAndWithVpn() throws {
        var (s, b) = try settings()
        s.zapretSites = ["youtube.com", "https://www.Discord.com/app"]
        let only = try parse(try ConfigBuilder.build(s, server: b, mac: .init(zapretPort: 21000, zapretOnly: true)))
        let route = try XCTUnwrap(only["route"] as? JSON)
        XCTAssertEqual(route["final"] as? String, "direct")
        let outs = try XCTUnwrap(only["outbounds"] as? [JSON])
        XCTAssertFalse(outs.contains { $0["tag"] as? String == "proxy" })
        XCTAssertEqual(outs.first { $0["tag"] as? String == "zapret" }?["server_port"] as? Int, 21000)
        let z = try XCTUnwrap((route["rules"] as? [JSON])?.first { $0["outbound"] as? String == "zapret" })
        XCTAssertEqual(z["domain_suffix"] as? [String], ["youtube.com", "discord.com"])
        let servers = try XCTUnwrap((only["dns"] as? JSON)?["servers"] as? [JSON])
        XCTAssertFalse(servers.contains { $0["detour"] != nil })
        let both = try parse(try ConfigBuilder.build(s, server: b, mac: .init(zapretPort: 21000)))
        XCTAssertTrue(((both["outbounds"] as? [JSON]) ?? []).contains { $0["tag"] as? String == "proxy" })
    }

    func testKillSwitchSelectedRoutesThroughVpn() throws {
        var (s, b) = try settings()
        s.killSwitch = true
        s.killSwitchScope = "selected"
        s.killSwitchSites = ["example.com", "198.51.100.0/24"]
        let rules = try XCTUnwrap((try parse(try ConfigBuilder.build(s, server: b))["route"] as? JSON)?["rules"] as? [JSON])
        XCTAssertTrue(rules.contains { ($0["domain_suffix"] as? [String]) == ["example.com"] && $0["outbound"] as? String == "proxy" })
        XCTAssertTrue(rules.contains { ($0["ip_cidr"] as? [String]) == ["198.51.100.0/24"] })
    }

    func testPfRules() {
        let all = MacRules.pfRules(scope: "all", servers: ["203.0.113.7", "vpn.example.com"], allowLan: true, blockedAddresses: [])
        XCTAssertTrue(all.contains("pass out quick on utun0 all"))
        XCTAssertTrue(all.contains("pass out quick to { 203.0.113.7 }"))
        XCTAssertFalse(all.contains("vpn.example.com"))
        XCTAssertTrue(all.contains("pass out quick to 192.168.0.0/16"))
        XCTAssertTrue(all.hasSuffix("block drop out quick all\n"))
        let sel = MacRules.pfRules(scope: "selected", servers: [], allowLan: false, blockedAddresses: ["198.51.100.0/24", "junk"])
        XCTAssertTrue(sel.contains("block drop out quick to { 198.51.100.0/24 }"))
        XCTAssertFalse(sel.contains("junk"))
        XCTAssertFalse(sel.contains("block drop out quick all"))
    }

    func testAddressesAndClean() {
        XCTAssertTrue(MacRules.isAddress("1.2.3.4"))
        XCTAssertTrue(MacRules.isAddress("10.0.0.0/8"))
        XCTAssertTrue(MacRules.isAddress("2001:db8::/32"))
        XCTAssertFalse(MacRules.isAddress("example.com"))
        XCTAssertFalse(MacRules.isAddress("1.2.3.4/40"))
        XCTAssertFalse(MacRules.isAddress("1.2.3"))
        XCTAssertEqual(MacRules.clean("https://www.Example.com/path"), "example.com")
        XCTAssertEqual(MacRules.clean("*.site.org."), "site.org")
    }

    func testOfficialCores() throws {
        let hy = try ShareLinks.parse("hy2://pass@hy.example.com:443?sni=hy.example.com&obfs=salamander&obfs-password=x&mport=20000-30000#hy2")
        let nv = try ShareLinks.parse("naive+https://user:pass@n.example.com:443#naive")
        XCTAssertNil(Engines.engine(hy))
        Engines.official = [.hysteria, .naive]
        defer { Engines.official = [] }
        XCTAssertEqual(Engines.engine(hy), .hysteria)
        XCTAssertEqual(Engines.engine(nv), .naive)
        let h = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(Engines.hysteriaConfig(hy, port: 21001, caFile: nil, ps: ProtocolSettings()).utf8)) as? JSON)
        XCTAssertEqual(h["server"] as? String, "hy.example.com:20000-30000")
        XCTAssertEqual((h["socks5"] as? JSON)?["listen"] as? String, "127.0.0.1:21001")
        XCTAssertEqual((h["obfs"] as? JSON)?["type"] as? String, "salamander")
        let n = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(Engines.naiveConfig(nv, port: 21002).utf8)) as? JSON)
        XCTAssertEqual(n["listen"] as? String, "socks://127.0.0.1:21002")
        XCTAssertEqual(n["proxy"] as? String, "https://user:pass@n.example.com:443")
    }

    func testTorArgumentsMac() {
        let a = Engines.torArgumentsMac(socksPort: 19050, dataDir: "/d", logFile: "/l", bridges: ["snowflake 192.0.2.3:80 FP", "obfs4 1.2.3.4:443 FP cert=x"], pt: "/pt", geoip: "/g")
        XCTAssertTrue(a.contains("snowflake exec /pt/snowflake-client"))
        XCTAssertTrue(a.contains("obfs4 exec /pt/lyrebird"))
        XCTAssertEqual(a.filter { $0 == "--Bridge" }.count, 2)
    }

    func testSelectivePresetGoesDirectByDefault() throws {
        var (s, b) = try settings()
        s.preset = .blocked
        let cfg = try parse(try ConfigBuilder.build(s, server: b))
        XCTAssertEqual((cfg["route"] as? JSON)?["final"] as? String, "direct")
        XCTAssertEqual((cfg["dns"] as? JSON)?["final"] as? String, "direct-dns")
    }

    func testCascadeDetour() throws {
        var (s, b) = try settings()
        s.cascadeEntryId = s.servers[0].id
        let cfg = try parse(try ConfigBuilder.build(s, server: b))
        let outs = try XCTUnwrap(cfg["outbounds"] as? [JSON])
        let proxy = try XCTUnwrap(outs.first { $0["tag"] as? String == "proxy" })
        XCTAssertEqual(proxy["detour"] as? String, "hop0")
        XCTAssertTrue(outs.contains { $0["tag"] as? String == "hop0" && $0["type"] as? String == "trojan" })
    }

    func testGroupIsUrltest() throws {
        var (s, _) = try settings()
        let g = Server(name: "g", kind: "group", server: "group", port: 1, members: s.servers.map(\.id))
        s.servers.append(g)
        let cfg = try parse(try ConfigBuilder.build(s, server: g))
        let outs = try XCTUnwrap(cfg["outbounds"] as? [JSON])
        let proxy = try XCTUnwrap(outs.first { $0["tag"] as? String == "proxy" })
        XCTAssertEqual(proxy["type"] as? String, "urltest")
        XCTAssertEqual((proxy["outbounds"] as? [String])?.count, 2)
    }

    func testExtraCoreOnlyFirstInCascade() throws {
        var (s, b) = try settings()
        let x = try ShareLinks.parse("vless://11111111-2222-3333-4444-555555555555@x.example.com:443?type=xhttp&security=tls#x")
        s.servers.append(x)
        // As the entry hop: fine (sing-box dials the exit through the local Xray port).
        s.cascadeEntryId = x.id
        let cfg = try parse(try ConfigBuilder.build(s, server: b, backends: [x.id: 20010]))
        let outs = try XCTUnwrap(cfg["outbounds"] as? [JSON])
        XCTAssertEqual(outs.first { $0["tag"] as? String == "proxy" }?["detour"] as? String, "hop0")
        // As the exit behind another hop: refused.
        s.cascadeEntryId = s.servers[0].id
        var exit = x; exit.viaId = s.servers[0].id
        s.servers[s.servers.count - 1] = exit
        XCTAssertThrowsError(try ConfigBuilder.build(s, server: exit, backends: [x.id: 20010]))
    }

    func testNaiveHasNoUdp() throws {
        var s = AppSettings()
        let n = try ShareLinks.parse("naive+https://user:pass@naive.example.com:443#n")
        s.servers = [n]
        let cfg = try parse(try ConfigBuilder.build(s, server: n))
        let rules = try XCTUnwrap((cfg["route"] as? JSON)?["rules"] as? [JSON])
        XCTAssertTrue(rules.contains { $0["action"] as? String == "reject" && ($0["network"] as? [String]) == ["udp"] })
    }
}
