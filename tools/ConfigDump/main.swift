// Writes the configs the app would generate for a set of scenarios, so real cores can check them
// (scripts/linux-check.sh: sing-box check; Xray and mihomo through core/internal/configcheck).
// Not part of the Xcode project.
import Foundation
@testable import SLMShared

let out = URL(fileURLWithPath: CommandLine.arguments.count > 1 ? CommandLine.arguments[1] : "configs")
try? FileManager.default.createDirectory(at: out, withIntermediateDirectories: true)

func link(_ l: String) -> Server { try! ShareLinks.parse(l) }
let uuid = "11111111-2222-3333-4444-555555555555"
let wgKey = "cHJpdmF0ZWtleXByaXZhdGVrZXlwcml2YXRla2V5MTI%3D"
let wgPub = "cHVibGlja2V5cHVibGlja2V5cHVibGlja2V5cHViMTI%3D"

let reality = link("vless://\(uuid)@r.example.com:443?type=tcp&security=reality&pbk=jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0&sid=ab12&sni=www.microsoft.com&fp=chrome&flow=xtls-rprx-vision#reality")
let ws = link("vless://\(uuid)@ws.example.com:443?type=ws&security=tls&path=%2Fws&host=cdn.example.com&sni=cdn.example.com#ws")
let trojan = link("trojan://pw@t.example.com:443?security=tls&sni=t.example.com&type=grpc&serviceName=g1#trojan")
let hy2 = link("hy2://pass@hy.example.com:443?sni=hy.example.com&obfs=salamander&obfs-password=x&mport=20000-30000#hy2")
let tuic = link("tuic://\(uuid):pw@[2001:db8::1]:8443?congestion_control=bbr&alpn=h3#tuic")
let anytls = link("anytls://pw@a.example.com:443?sni=a.example.com#anytls")
let naive = link("naive+https://user:pass@n.example.com:443#naive")
let ss = link("ss://" + Data("2022-blake3-aes-128-gcm:c2VjcmV0c2VjcmV0MTIzNA==".utf8).base64EncodedString() + "@1.2.3.4:8388#ss")
let stls = link("ss://" + Data("2022-blake3-aes-128-gcm:c2VjcmV0c2VjcmV0MTIzNA==".utf8).base64EncodedString() + "@1.2.3.4:443?plugin=shadow-tls%3Bhost%3Dwww.microsoft.com%3Bpassword%3Dx%3Bversion%3D3#stls")
let wg = link("wireguard://\(wgKey)@1.2.3.4:51820?publickey=\(wgPub)&address=10.8.0.2/32&reserved=1,2,3#wg")
let awg = link("wireguard://\(wgKey)@1.2.3.4:51820?publickey=\(wgPub)&address=10.8.0.2/32&jc=4&jmin=40&jmax=70&h1=1&i1=%3Cb%200x01%3E#awg")
let xhttp = link("vless://\(uuid)@x.example.com:443?type=xhttp&security=tls&sni=x.example.com&path=%2Fx&mode=auto#xhttp")
let mieru = link("mierus://alice:secret@m.example.com?port=8964&protocol=TCP#mieru")
let ssr = link("ssr://" + Data("1.2.3.4:8388:origin:aes-256-cfb:plain:\(Data("pw".utf8).base64EncodedString())/?remarks=".utf8).base64EncodedString())
var tt = Server(name: "tt", kind: "tt", server: "vpn.example.com", port: 443, userId: "u", password: "p",
                params: ["addresses": "1.2.3.4:443", "upstream": "http2"])
tt = link(MoreLinks.ttLink(tt))
let tor = MoreLinks.torProfile(transport: "obfs4")

let all = [reality, ws, trojan, hy2, tuic, anytls, naive, ss, stls, wg, awg, xhttp, mieru, ssr, tt, tor]

func write(_ name: String, _ text: String) {
    try! Data(text.utf8).write(to: out.appendingPathComponent(name))
    print("wrote", name)
}

func singBox(_ name: String, _ s: AppSettings, _ server: Server) {
    let backends = Dictionary(uniqueKeysWithValues: Engines.backends(s, server).enumerated().map { ($1.id, 21000 + $0) })
    do { write("singbox-\(name).json", try ConfigBuilder.build(s, server: server, backends: backends)) }
    catch { print("ERROR \(name): \(error.localizedDescription)"); exit(1) }
}

// Every server alone, with every preset/feature switched on at least once.
for (i, s) in all.enumerated() {
    var st = AppSettings()
    st.servers = all
    st.activeId = s.id
    st.preset = [.all, .exceptRu, .blocked][i % 3]
    st.callsViaVpn = i % 2 == 0
    st.ipv6 = i % 4 == 0
    st.customRules = [CustomRule(name: "r", action: ["vpn", "direct", "block"][i % 3], domains: ["example.org"], ips: ["1.2.3.4", "10.0.0.0/8"])]
    st.protocols.tlsFragment = i % 2 == 1
    st.protocols.multiplex = i % 5 == 0 ? "h2mux" : ""
    singBox("\(s.kind)-\(s.name)", st, s)
}

// Cascade: XHTTP (Xray) as the entry, Reality as the exit; and a group with WireGuard + Hysteria2.
var c = AppSettings()
let group = Server(name: "group", kind: "group", server: "group", port: 1, members: [reality.id, hy2.id, wg.id, xhttp.id])
c.servers = all + [group]
c.cascadeEntryId = xhttp.id
singBox("cascade-xray-entry", c, reality)
c.cascadeEntryId = trojan.id
singBox("cascade-group", c, group)

// Extra-core configs.
write("xray.json", Engines.xrayConfig(xhttp, port: 21000, logLevel: "warn"))
write("mihomo.json", Engines.mihomoConfig([(awg, 21001), (mieru, 21002), (ssr, 21003)], logLevel: "warn"))
write("trusttunnel.toml", Engines.ttConfig(tt, port: 21004))

// ---- macOS: TUN with program rules, kill switch sites, Zapret; official cores; Tor arguments ----
func macConfig(_ name: String, _ s: AppSettings, _ server: Server, _ mac: ConfigBuilder.Mac) {
    let backends = mac.zapretOnly ? [:] : Dictionary(uniqueKeysWithValues: Engines.backends(s, server).enumerated().map { ($1.id, 21000 + $0) })
    do { write("singbox-mac-\(name).json", try ConfigBuilder.build(s, server: server, backends: backends, mac: mac)) }
    catch { print("ERROR mac \(name): \(error.localizedDescription)"); exit(1) }
}
var m = AppSettings()
m.servers = all
m.appRules = [AppRule(process: "Telegram", action: "vpn"), AppRule(process: "Zoom", action: "block"), AppRule(process: "Safari", action: "direct")]
m.gamesViaVpn = true
m.ownServices = [OwnService(name: "own", group: "ai", domains: ["my-ai.example"], ips: ["203.0.113.5"], processes: ["MyAI"])]
m.killSwitch = true
m.killSwitchScope = "selected"
m.killSwitchSites = ["example.com", "198.51.100.0/24"]
m.blockLists = []
macConfig("tun-rules", m, reality, .init(tun: true, zapretPort: 21100, ownProcesses: ["xray", "mihomo", "tpws"]))
macConfig("proxy", m, trojan, .init())
// Zapret only: the configs the CI smoke test runs for real (sing-box + tpws, in proxy mode and through the helper in TUN).
var z = AppSettings()
z.mixedPort = Int(ProcessInfo.processInfo.environment["SLM_MIXED_PORT"] ?? "") ?? 10808
z.zapretSites = ["example.com", "example.org"]
let zport = Int(ProcessInfo.processInfo.environment["SLM_ZAPRET_PORT"] ?? "") ?? 21200
macConfig("zapret-only", z, Server(name: "Zapret", kind: "zapret"), .init(zapretPort: zport, zapretOnly: true))
macConfig("zapret-only-tun", z, Server(name: "Zapret", kind: "zapret"), .init(tun: true, zapretPort: zport, ownProcesses: ["tpws"], zapretOnly: true))
Engines.official = [.hysteria, .naive]
write("hysteria.json", Engines.hysteriaConfig(hy2, port: 21005, caFile: nil, ps: ProtocolSettings()))
write("naive.json", Engines.naiveConfig(naive, port: 21006))
Engines.official = []
print("mac configs written")
