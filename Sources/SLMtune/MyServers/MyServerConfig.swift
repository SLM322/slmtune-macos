import Crypto
import Foundation
@testable import SLMShared
import SwiftASN1
import X509

/// Bash scripts sent over SSH: the same .sh files as the Windows/Android versions (Resources/server, generated from
/// ServerSetup.cs by tools/gen_server_scripts.py) so all apps set up a server exactly the same way.
enum ServerScripts {
    static func s(_ name: String) -> String {
        guard let url = Bundle.main.url(forResource: name, withExtension: "sh"),
              let text = try? String(contentsOf: url, encoding: .utf8) else { return "echo 'missing script \(name)'; exit 1\n" }
        return text
    }

    static func b64(_ v: String) -> String { Data(v.utf8).base64EncodedString() }
    private static func trimmed(_ name: String) -> String {
        var t = s(name)
        while t.hasSuffix("\n") { t.removeLast() }
        return t + "\n"
    }

    static var probe: String { s("Probe") }
    static var restart: String { s("Restart") }
    static var updateSingBox: String { s("UpdateSingBox") }
    static var harden: String { s("Pkg") + s("Harden") }
    static var swapAndTime: String { s("SwapAndTime") }
    static var autoUpdates: String { s("Pkg") + s("AutoUpdates") }
    static var netCheck: String { s("NetCheck") }
    static var ttRemove: String { s("TtRemove") }
    static let reboot = "set +e\necho \"[slm] rebooting in 2 seconds\"\nnohup sh -c 'sleep 2; systemctl reboot' >/dev/null 2>&1 &\necho \"tools=ok\"\n"
    static let logs = "systemctl --no-pager status sing-box 2>&1 | head -12; journalctl -u sing-box -n 30 --no-pager 2>&1; " +
        "if [ -f /opt/trusttunnel/slm-managed ]; then systemctl --no-pager status trusttunnel 2>&1 | head -8; journalctl -u trusttunnel -n 20 --no-pager 2>&1; fi"

    static func ensureSingBox(realityKeys: Bool) -> String {
        s("EnsureSingBox") + (realityKeys
            ? "\nsing-box generate reality-keypair | sed -e 's/^PrivateKey: */reality_private=/' -e 's/^PublicKey: */reality_public=/'\n"
            : "\n")
    }

    static func installKey(_ publicKey: String) -> String { s("InstallKey").replacingOccurrences(of: "{{publicKey}}", with: publicKey) }

    static func resetUsage(_ id: Int) -> String { "set -e\npython3 /etc/sing-box/slm-usage.py reset \(id)\necho \"reset=ok\"\n" }

    static func accounting(_ nft: String) -> String {
        s("Accounting")
            .replacingOccurrences(of: "{{B64(UsageScript)}}", with: b64(trimmed("UsageScript")))
            .replacingOccurrences(of: "{{B64(nft)}}", with: b64(nft))
            .replacingOccurrences(of: "{{B64(AcctUnit)}}", with: b64(trimmed("AcctUnit")))
            .replacingOccurrences(of: "{{B64(UsageUnit)}}", with: b64(trimmed("UsageUnit")))
            .replacingOccurrences(of: "{{B64(UsageTimer)}}", with: b64(trimmed("UsageTimer")))
    }

    /// Uploads the config (checked by sing-box first), restarts it, opens/closes firewall ports, BBR, accounting.
    static func apply(config: String, meta: String, open: [String], close: [String], bbr: Bool, singBox: Bool, nft: String?) -> String {
        var t = s("Apply")
        if singBox { t += s("Apply2").replacingOccurrences(of: "{{B64(configJson)}}", with: b64(config)) }
        t += s("Apply3").replacingOccurrences(of: "{{B64(metaJson)}}", with: b64(meta))
        for p in close { t += "closep '\(p)'\n" }
        for p in open { t += "openp '\(p)'\n" }
        t += "if [ \"$FWD\" = running ]; then firewall-cmd -q --reload; fi\n"
        if bbr { t += s("Apply4") }
        if let nft { t += accounting(nft) }
        return t + "echo \"apply=ok\"\n"
    }

    static func ttApply(vpn: String, hosts: String, creds: String, cert: String, key: String) -> String {
        s("TtApply")
            .replacingOccurrences(of: "{{B64(certPem)}}", with: b64(cert)).replacingOccurrences(of: "{{B64(keyPem)}}", with: b64(key))
            .replacingOccurrences(of: "{{B64(vpnToml)}}", with: b64(vpn)).replacingOccurrences(of: "{{B64(hostsToml)}}", with: b64(hosts))
            .replacingOccurrences(of: "{{B64(credentialsToml)}}", with: b64(creds))
    }
}

/// What the server reported (ServerScripts.probe).
struct ServerInfo {
    var os = "", arch = "", singBox = "", singBoxActive = "", congestion = "", ufw = "", firewalld = "", ttActive = ""
    var ttInstalled = false, ttManaged = false, accounting = false
    var listening: [(proto: String, port: Int, process: String)] = []
    var config: JSON?, meta: JSON?, usage: JSON?
    var load = 0.0, cpus = 0
    var memUsed: Int64 = 0, memTotal: Int64 = 0, diskUsed: Int64 = 0, diskTotal: Int64 = 0, uptime: Int64 = 0

    static func parse(_ output: String) -> ServerInfo {
        var i = ServerInfo()
        func obj(_ v: String) -> JSON? {
            guard let d = Data(base64Encoded: v) else { return nil }
            return try? JSONSerialization.jsonObject(with: d) as? JSON
        }
        func pair(_ v: String) -> (Int64, Int64) {
            let p = v.split(separator: "/")
            return p.count == 2 ? (Int64(p[0]) ?? 0, Int64(p[1]) ?? 0) : (0, 0)
        }
        for raw in output.split(separator: "\n") {
            let line = raw.trimmingCharacters(in: CharacterSet(charactersIn: "\r"))
            guard let eq = line.firstIndex(of: "="), eq != line.startIndex else { continue }
            let k = String(line[..<eq]), v = String(line[line.index(after: eq)...]).trimmingCharacters(in: .whitespaces)
            switch k {
            case "os": i.os = v
            case "arch": i.arch = v
            case "singbox": i.singBox = v
            case "singbox_active": i.singBoxActive = v
            case "cc": i.congestion = v
            case "ufw": i.ufw = v
            case "firewalld": i.firewalld = v
            case "tt_installed": i.ttInstalled = v == "1"
            case "tt_managed": i.ttManaged = v == "1"
            case "tt_active": i.ttActive = v
            case "config": i.config = obj(v)
            case "meta": i.meta = obj(v)
            case "usage": i.usage = obj(v)
            case "acct": i.accounting = v == "on"
            case "load": i.load = Double(v) ?? 0
            case "cpus": i.cpus = Int(v) ?? 0
            case "mem": (i.memUsed, i.memTotal) = pair(v)
            case "disk": (i.diskUsed, i.diskTotal) = pair(v)
            case "uptime": i.uptime = Int64(v) ?? 0
            case "listen":
                // "tcp 0.0.0.0:443 users:(("sing-box",pid=1,fd=3))"
                let parts = v.split(separator: " ", maxSplits: 2).map(String.init)
                guard parts.count >= 2, let port = Int(parts[1].components(separatedBy: ":").last ?? "") else { continue }
                var proc = ""
                if parts.count > 2, let q1 = parts[2].firstIndex(of: "\"") {
                    let rest = parts[2][parts[2].index(after: q1)...]
                    proc = String(rest.prefix { $0 != "\"" })
                }
                let proto = parts[0].hasPrefix("udp") ? "udp" : "tcp"
                if !i.listening.contains(where: { $0.proto == proto && $0.port == port }) { i.listening.append((proto, port, proc)) }
            default: break
            }
        }
        return i
    }

    /// Who holds the port, unless it is our own sing-box (which is about to be reconfigured anyway).
    func portOwner(_ port: Int, _ proto: String) -> String? {
        guard let l = listening.first(where: { $0.port == port && $0.proto == proto }) else { return nil }
        return l.process == "sing-box" ? nil : (l.process.isEmpty ? "?" : l.process)
    }
}

struct MyUser: Identifiable, Hashable {
    var name = "", uuid = "", pass = "", ssKey = ""
    /// Stable number: the user's packet mark and counter name on the server.
    var id = 0
    var off = false
    /// Traffic limit in bytes, 0 = none.
    var limit: Int64 = 0
    /// Last valid day "2026-11-30" (UTC), "" = no end.
    var expires = ""
    var note = ""

    static func bytes(_ n: Int) -> Data {
        var b = [UInt8](repeating: 0, count: n)
        _ = SecRandomCopyBytes(kSecRandomDefault, n, &b)
        return Data(b)
    }
    static func b64url(_ d: Data) -> String {
        d.base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
    }
    static func hex(_ d: Data) -> String { d.map { String(format: "%02x", $0) }.joined() }

    static func create(_ name: String, id: Int) -> MyUser {
        MyUser(name: name, uuid: UUID().uuidString.lowercased(), pass: b64url(bytes(18)), ssKey: bytes(16).base64EncodedString(), id: id)
    }
}

/// Our part of the server's sing-box config (port of MyServerConfig). The truth lives on the server:
/// /etc/sing-box/slm-meta.json (users, keys, ports) → the inbounds tagged slm-*; anything else in config.json is kept.
final class MyServerConfig {
    static let vlessTag = "slm-vless", hy2Tag = "slm-hy2", ssTag = "slm-ss", naiveTag = "slm-naive", trojanTag = "slm-trojan"
    static let tuicTag = "slm-tuic", anytlsTag = "slm-anytls", wsTag = "slm-vless-ws", grpcTag = "slm-vless-grpc", socksTag = "slm-socks"
    static let stlsTag = "slm-stls", stlsInner = "slm-stls-ss"
    static let ourTags: Set<String> = [vlessTag, hy2Tag, ssTag, naiveTag, trojanTag, tuicTag, anytlsTag, wsTag, grpcTag, socksTag, stlsTag, stlsInner]
    static let userOut = "slm-u-"
    static let markBase = 21000
    static let ssMethod = "2022-blake3-aes-128-gcm"
    static let protoKeys = ["vless", "hy2", "ss", "naive", "tt", "trojan", "tuic", "anytls", "vless_ws", "vless_grpc", "socks", "shadowtls"]

    var users: [MyUser] = []
    /// Installed protocols by meta key; absent = not installed.
    var proto: [String: JSON] = [:]
    var usage: JSON?
    var singBoxVersion = ""
    private var base: JSON = [:]

    static func from(_ info: ServerInfo) -> MyServerConfig {
        let c = MyServerConfig()
        c.base = info.config ?? [:]
        if let m = info.meta {
            for o in (m["users"] as? [JSON]) ?? [] {
                func str(_ k: String) -> String { o[k] as? String ?? "" }
                c.users.append(MyUser(name: str("name"), uuid: str("uuid"), pass: str("pass"), ssKey: str("ss"),
                                      id: (o["id"] as? NSNumber)?.intValue ?? 0, off: (o["off"] as? Bool) ?? false,
                                      limit: (o["limit"] as? NSNumber)?.int64Value ?? 0, expires: str("exp"), note: str("note")))
            }
            for i in c.users.indices where c.users[i].id <= 0 { c.users[i].id = c.nextUserId() }
            for k in protoKeys { if let p = m[k] as? JSON { c.proto[k] = p } }
        }
        c.usage = info.usage
        if !info.ttManaged { c.proto.removeValue(forKey: "tt") }
        c.singBoxVersion = info.singBox
        return c
    }

    static func mark(_ u: MyUser) -> Int { markBase + u.id }

    /// A free name that points at the IP (sslip.io), or the host itself when it is already a domain.
    static func defaultDomain(_ host: String) -> String {
        host.range(of: #"^\d{1,3}(\.\d{1,3}){3}$"#, options: .regularExpression) != nil
            ? host.replacingOccurrences(of: ".", with: "-") + ".sslip.io" : host
    }

    private static func ver(_ v: String) -> Int? {
        let p = v.components(separatedBy: "-")[0].components(separatedBy: ".")
        guard p.count >= 2, let a = Int(p[0]), let b = Int(p[1]) else { return nil }
        return a * 1000 + b
    }
    static func supportsAnyTls(_ version: String) -> Bool { ver(version).map { $0 >= 1012 } ?? true }
    private static func needsInlineAcme(_ v: String) -> Bool { ver(v).map { $0 < 1014 } ?? false }

    /// A self-signed ECDSA P-256 certificate (Hysteria2, TrustTunnel); the client pins exactly this one.
    static func selfSigned(_ cn: String) throws -> (cert: String, key: String) {
        let key = P256.Signing.PrivateKey()
        let name = try DistinguishedName { CommonName(cn) }
        let now = Date()
        let cert = try Certificate(
            version: .v3, serialNumber: Certificate.SerialNumber(),
            publicKey: .init(key.publicKey),
            notValidBefore: now.addingTimeInterval(-86_400), notValidAfter: now.addingTimeInterval(3650 * 86_400),
            issuer: name, subject: name, signatureAlgorithm: .ecdsaWithSHA256,
            extensions: try Certificate.Extensions { SubjectAlternativeNames([.dnsName(cn)]) },
            issuerPrivateKey: .init(key))
        let certPem = try cert.serializeAsPEM().pemString + "\n"
        return (certPem, key.pemRepresentation + "\n")
    }

    static func certSha256Hex(_ pem: String) -> String {
        guard let der = MoreLinks.pemCertificates(pem).first else { return "" }
        return SHA256.hash(data: der).map { String(format: "%02x", $0) }.joined()
    }

    private static func enc(_ v: String) -> String {
        v.addingPercentEncoding(withAllowedCharacters: .urlQueryValueAllowed)?.replacingOccurrences(of: "+", with: "%2B") ?? v
    }

    func str(_ k: String, _ f: String) -> String { (proto[k]?[f] as? String) ?? (proto[k]?[f] as? NSNumber)?.stringValue ?? "" }
    func port(_ k: String) -> Int { (proto[k]?["port"] as? NSNumber)?.intValue ?? defaultPort(k) }
    func has(_ k: String) -> Bool { proto[k] != nil }

    func defaultPort(_ k: String) -> Int {
        switch k {
        case "vless", "hy2", "naive": return 443
        case "ss": return 8388
        case "tt": return 9443
        case "trojan", "tuic": return 8443
        case "anytls": return 2096
        case "vless_ws": return 2087
        case "vless_grpc": return 2053
        case "socks": return 1080
        case "shadowtls": return 8444
        default: return 443
        }
    }

    var hasSingBoxProtocols: Bool { proto.keys.contains { $0 != "tt" } }
    var anyProtocol: Bool { !proto.isEmpty }
    var needsAcme: Bool { ["naive", "trojan", "tuic", "anytls", "vless_ws", "vless_grpc"].contains { has($0) } }
    func domain(_ host: String) -> String {
        ["tt", "naive", "trojan", "tuic", "anytls", "vless_ws", "vless_grpc"].map { str($0, "domain") }.first { !$0.isEmpty }
            ?? Self.defaultDomain(host)
    }
    var realitySni: String { str("vless", "sni").isEmpty ? "www.microsoft.com" : str("vless", "sni") }
    var shadowTlsSni: String { str("shadowtls", "sni").isEmpty ? "www.microsoft.com" : str("shadowtls", "sni") }
    var active: [MyUser] { users.filter { !$0.off } }
    func nextUserId() -> Int { max(users.map(\.id).max() ?? 0, 0) + 1 }

    /// Bytes the server counted for the user (sing-box protocols only).
    func usage(_ u: MyUser) -> (up: Int64, down: Int64) {
        let e = (usage?["users"] as? JSON)?["\(u.id)"] as? JSON
        return ((e?["up"] as? NSNumber)?.int64Value ?? 0, (e?["down"] as? NSNumber)?.int64Value ?? 0)
    }

    /// "off" by hand, "expired" / "limit" by the server, otherwise "on".
    func state(_ u: MyUser, today: String) -> String {
        if u.off { return "off" }
        if !u.expires.isEmpty, today > u.expires { return "expired" }
        let (up, down) = usage(u)
        return u.limit > 0 && up + down >= u.limit ? "limit" : "on"
    }

    /// Firewall entries ("443/tcp") of what is installed.
    func ports() -> [String] {
        var l: [String] = []
        if has("vless") { l.append("\(port("vless"))/tcp") }
        if has("hy2") { l.append("\(port("hy2"))/udp") }
        if has("ss") { l += ["\(port("ss"))/tcp", "\(port("ss"))/udp"] }
        if has("naive") { l.append("\(port("naive"))/tcp") }
        if has("tt") { l += ["\(port("tt"))/tcp", "\(port("tt"))/udp"] }
        if has("trojan") { l.append("\(port("trojan"))/tcp") }
        if has("tuic") { l.append("\(port("tuic"))/udp") }
        if has("anytls") { l.append("\(port("anytls"))/tcp") }
        if has("vless_ws") { l.append("\(port("vless_ws"))/tcp") }
        if has("vless_grpc") { l.append("\(port("vless_grpc"))/tcp") }
        if has("socks") { l += ["\(port("socks"))/tcp", "\(port("socks"))/udp"] }
        if has("shadowtls") { l.append("\(port("shadowtls"))/tcp") }
        return l
    }

    private func set(_ k: String, _ values: JSON) {
        var o = proto[k] ?? [:]
        for (key, v) in values { o[key] = v }
        proto[k] = o
    }

    func remove(_ k: String) { proto.removeValue(forKey: k) }
    func setPlain(_ k: String, port: Int, domain: String) { set(k, ["port": port, "domain": domain]) }
    func setVlessWs(_ port: Int, _ domain: String) {
        set("vless_ws", ["port": port, "domain": domain])
        if str("vless_ws", "path").isEmpty { set("vless_ws", ["path": "/" + MyUser.hex(MyUser.bytes(6))]) }
    }
    func setVlessGrpc(_ port: Int, _ domain: String) {
        set("vless_grpc", ["port": port, "domain": domain])
        if str("vless_grpc", "service").isEmpty { set("vless_grpc", ["service": "g" + MyUser.hex(MyUser.bytes(5))]) }
    }
    func setShadowTls(_ port: Int, _ sni: String) {
        if !has("shadowtls") { proto["shadowtls"] = ["key": MyUser.bytes(16).base64EncodedString(), "inner": 20000 + Int.random(in: 0..<20000)] }
        set("shadowtls", ["port": port, "sni": sni])
    }
    func setSocks(_ port: Int) { set("socks", ["port": port]) }
    func setTt(_ port: Int, _ domain: String) throws {
        if !has("tt") || str("tt", "domain") != domain {
            let (cert, key) = try Self.selfSigned(domain)
            proto["tt"] = ["cert": cert, "key": key]
        }
        set("tt", ["port": port, "domain": domain])
    }
    func setVless(_ port: Int, sni: String, privateKey: String?, publicKey: String?) {
        if !has("vless") { proto["vless"] = ["sid": MyUser.hex(MyUser.bytes(8))] }
        set("vless", ["port": port, "sni": sni])
        if let privateKey { set("vless", ["priv": privateKey]) }
        if let publicKey { set("vless", ["pub": publicKey]) }
    }
    var vlessNeedsKeys: Bool { !has("vless") || str("vless", "priv").isEmpty }
    func setHy2(_ port: Int) throws {
        if !has("hy2") {
            let sni = "www.bing.com"
            let (cert, key) = try Self.selfSigned(sni)
            proto["hy2"] = ["sni": sni, "cert": cert, "key": key, "obfs": MyUser.b64url(MyUser.bytes(18))]
        }
        set("hy2", ["port": port])
    }
    func setSs(_ port: Int) {
        if !has("ss") { proto["ss"] = ["key": MyUser.bytes(16).base64EncodedString()] }
        set("ss", ["port": port])
    }

    func addUser(_ name: String) throws {
        if users.contains(where: { $0.name.caseInsensitiveCompare(name) == .orderedSame }) { throw SSH.Failed(L("Такой пользователь уже есть.")) }
        users.append(MyUser.create(name, id: nextUserId()))
    }

    // MARK: TrustTunnel endpoint files

    func ttVpnToml() -> String { ServerScripts.s("TtVpnToml").replacingOccurrences(of: "{{TtPort}}", with: "\(port("tt"))") }
    func ttHostsToml() -> String { ServerScripts.s("TtHostsToml").replacingOccurrences(of: "{{S(Tt!, \"domain\")}}", with: str("tt", "domain")) }
    func ttCredentialsToml() -> String { active.map { "[[client]]\nusername = \(tq($0.name))\npassword = \(tq($0.pass))\n\n" }.joined() }
    private func tq(_ v: String) -> String { "\"" + v.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "\"", with: "\\\"") + "\"" }

    /// The nftables ruleset behind traffic accounting (counted per packet mark, "blocked" set dropped).
    func nftRules() -> String {
        var t = "table inet slm\ndelete table inet slm\ntable inet slm {\n\tset blocked { type mark; }\n"
        for u in users { t += "\tcounter up_\(u.id) { packets 0 bytes 0 }\n\tcounter down_\(u.id) { packets 0 bytes 0 }\n" }
        t += "\tchain out {\n\t\ttype filter hook output priority 0; policy accept;\n"
        t += "\t\tmeta mark \(Self.markBase)-\(Self.markBase + 8999) ct mark set meta mark\n\t\tmeta mark @blocked drop\n"
        for u in users { t += "\t\tmeta mark \(Self.mark(u)) counter name \"up_\(u.id)\"\n" }
        t += "\t}\n\tchain in {\n\t\ttype filter hook input priority 0; policy accept;\n\t\tct mark @blocked drop\n"
        for u in users { t += "\t\tct mark \(Self.mark(u)) counter name \"down_\(u.id)\"\n" }
        return t + "\t}\n}\n"
    }

    private func json(_ o: Any) -> String {
        String(decoding: (try? JSONSerialization.data(withJSONObject: o, options: [.sortedKeys, .withoutEscapingSlashes])) ?? Data(), as: UTF8.self)
    }

    func metaJson() -> String {
        var m: JSON = ["users": users.map { u -> JSON in
            ["name": u.name, "uuid": u.uuid, "pass": u.pass, "ss": u.ssKey, "id": u.id, "off": u.off,
             "limit": u.limit, "exp": u.expires, "note": u.note]
        }]
        for (k, v) in proto { m[k] = v }
        return json(m)
    }

    /// The whole config.json: foreign inbounds kept, ours rebuilt from the meta.
    func configJson() -> String {
        var cfg = base
        if cfg["log"] == nil { cfg["log"] = ["level": "warn", "timestamp": true] as JSON }
        func tagOf(_ e: Any) -> String? { (e as? JSON)?["tag"] as? String }
        var inbounds = ((cfg["inbounds"] as? [Any]) ?? []).filter { !Self.ourTags.contains(tagOf($0) ?? "") }
        func usersOf(_ f: (MyUser) -> JSON) -> [JSON] { active.map(f) }
        let inline = Self.needsInlineAcme(singBoxVersion)
        func acmeTls(_ domain: String, _ alpn: [String] = []) -> JSON {
            var t: JSON = ["enabled": true, "server_name": domain]
            if !alpn.isEmpty { t["alpn"] = alpn }
            var acme: JSON = ["domain": [domain], "data_directory": "/var/lib/sing-box/acme"]
            if !inline { acme["type"] = "acme" }
            t[inline ? "acme" : "certificate_provider"] = acme
            return t
        }
        func inbound(_ type: String, _ tag: String, _ port: Int, _ body: JSON) -> JSON {
            var o: JSON = ["type": type, "tag": tag, "listen": "::", "listen_port": port]
            for (k, v) in body { o[k] = v }
            return o
        }
        if has("vless") {
            inbounds.append(inbound("vless", Self.vlessTag, port("vless"), [
                "users": usersOf { ["name": $0.name, "uuid": $0.uuid, "flow": "xtls-rprx-vision"] },
                "tls": ["enabled": true, "server_name": realitySni, "reality": [
                    "enabled": true, "handshake": ["server": realitySni, "server_port": 443] as JSON,
                    "private_key": str("vless", "priv"), "short_id": [str("vless", "sid")],
                ] as JSON] as JSON,
            ]))
        }
        if has("hy2") {
            inbounds.append(inbound("hysteria2", Self.hy2Tag, port("hy2"), [
                "users": usersOf { ["name": $0.name, "password": $0.pass] },
                "obfs": ["type": "salamander", "password": str("hy2", "obfs")],
                "tls": ["enabled": true, "server_name": str("hy2", "sni"), "alpn": ["h3"],
                        "certificate": str("hy2", "cert"), "key": str("hy2", "key")] as JSON,
            ]))
        }
        if has("ss") {
            inbounds.append(inbound("shadowsocks", Self.ssTag, port("ss"), [
                "method": Self.ssMethod, "password": str("ss", "key"),
                "users": usersOf { ["name": $0.name, "password": $0.ssKey] },
            ]))
        }
        if has("naive") {
            inbounds.append(inbound("naive", Self.naiveTag, port("naive"), [
                "users": usersOf { ["username": $0.name, "password": $0.pass] }, "tls": acmeTls(str("naive", "domain")),
            ]))
        }
        if has("trojan") {
            inbounds.append(inbound("trojan", Self.trojanTag, port("trojan"), [
                "users": usersOf { ["name": $0.name, "password": $0.pass] }, "tls": acmeTls(str("trojan", "domain")),
            ]))
        }
        if has("tuic") {
            inbounds.append(inbound("tuic", Self.tuicTag, port("tuic"), [
                "users": usersOf { ["name": $0.name, "uuid": $0.uuid, "password": $0.pass] },
                "congestion_control": "bbr", "tls": acmeTls(str("tuic", "domain"), ["h3"]),
            ]))
        }
        if has("anytls") {
            inbounds.append(inbound("anytls", Self.anytlsTag, port("anytls"), [
                "users": usersOf { ["name": $0.name, "password": $0.pass] }, "tls": acmeTls(str("anytls", "domain")),
            ]))
        }
        let vlessUsers = usersOf { ["name": $0.name, "uuid": $0.uuid] }
        if has("vless_ws") {
            inbounds.append(inbound("vless", Self.wsTag, port("vless_ws"), [
                "users": vlessUsers, "transport": ["type": "ws", "path": str("vless_ws", "path")],
                "tls": acmeTls(str("vless_ws", "domain"), ["http/1.1"]),
            ]))
        }
        if has("vless_grpc") {
            inbounds.append(inbound("vless", Self.grpcTag, port("vless_grpc"), [
                "users": vlessUsers, "transport": ["type": "grpc", "service_name": str("vless_grpc", "service")],
                "tls": acmeTls(str("vless_grpc", "domain"), ["h2"]),
            ]))
        }
        if has("shadowtls") {
            inbounds.append(inbound("shadowtls", Self.stlsTag, port("shadowtls"), [
                "version": 3, "users": usersOf { ["name": $0.name, "password": $0.pass] },
                "handshake": ["server": shadowTlsSni, "server_port": 443] as JSON, "strict_mode": true, "detour": Self.stlsInner,
            ]))
            inbounds.append([
                "type": "shadowsocks", "tag": Self.stlsInner, "listen": "127.0.0.1",
                "listen_port": (proto["shadowtls"]?["inner"] as? NSNumber)?.intValue ?? 28388,
                "method": Self.ssMethod, "password": str("shadowtls", "key"),
                "users": usersOf { ["name": $0.name, "password": $0.ssKey] },
            ] as JSON)
        }
        if has("socks") {
            inbounds.append(inbound("socks", Self.socksTag, port("socks"), ["users": usersOf { ["username": $0.name, "password": $0.pass] }]))
        }
        cfg["inbounds"] = inbounds

        // Outbounds: foreign ones kept, ours ("slm-u-ID", one per user, each with its packet mark) rebuilt.
        func ours(_ e: Any, _ key: String) -> Bool { ((e as? JSON)?[key] as? String)?.hasPrefix(Self.userOut) == true }
        var outbounds = ((cfg["outbounds"] as? [Any]) ?? []).filter { !ours($0, "tag") }
        if outbounds.isEmpty { outbounds.append(["type": "direct", "tag": "direct"]) }
        var route = (cfg["route"] as? JSON) ?? [:]
        var rules = ((route["rules"] as? [Any]) ?? []).filter { !ours($0, "outbound") }
        let ourIn = inbounds.compactMap(tagOf).filter { Self.ourTags.contains($0) }
        if !ourIn.isEmpty {
            for (i, u) in active.enumerated() {
                outbounds.append(["type": "direct", "tag": Self.userOut + "\(u.id)", "routing_mark": Self.mark(u)] as JSON)
                // No "action": plain "outbound" rules are understood by every sing-box version.
                rules.insert(["inbound": ourIn, "auth_user": [u.name], "outbound": Self.userOut + "\(u.id)"] as JSON, at: min(i, rules.count))
            }
        }
        cfg["outbounds"] = outbounds
        if !rules.isEmpty { route["rules"] = rules; cfg["route"] = route }
        else if cfg["route"] != nil { route.removeValue(forKey: "rules"); if route.isEmpty { cfg.removeValue(forKey: "route") } else { cfg["route"] = route } }
        return json(cfg)
    }

    /// Share links for one user (what the app imports and what other clients understand).
    func links(host: String, user u: MyUser, label: String) -> [(title: String, link: String)] {
        let h = host.contains(":") ? "[\(host)]" : host
        func frag(_ p: String) -> String { "#" + Self.enc("\(label) · \(p)" + (u.name == "me" ? "" : " · \(u.name)")) }
        let e = Self.enc
        var l: [(String, String)] = []
        if has("vless") { l.append(("VLESS Reality", "vless://\(u.uuid)@\(h):\(port("vless"))?encryption=none&flow=xtls-rprx-vision&security=reality&sni=\(realitySni)&fp=chrome&pbk=\(str("vless", "pub"))&sid=\(str("vless", "sid"))&type=tcp\(frag("VLESS Reality"))")) }
        if has("hy2") { l.append(("Hysteria2", "hysteria2://\(u.pass)@\(h):\(port("hy2"))?sni=\(str("hy2", "sni"))&alpn=h3&obfs=salamander&obfs-password=\(e(str("hy2", "obfs")))&insecure=1&pinSHA256=\(Self.certSha256Hex(str("hy2", "cert")))\(frag("Hysteria2"))")) }
        if has("ss") { l.append(("Shadowsocks 2022", "ss://\(Self.ssMethod):\(e(str("ss", "key") + ":" + u.ssKey))@\(h):\(port("ss"))\(frag("Shadowsocks 2022"))")) }
        if has("naive") { l.append(("NaiveProxy", "naive+https://\(e(u.name)):\(e(u.pass))@\(str("naive", "domain")):\(port("naive"))\(frag("NaiveProxy"))")) }
        if has("tt") { l.append(("TrustTunnel", MoreLinks.ttLink(ttProfile(host: host, user: u, label: label)))) }
        if has("trojan") { l.append(("Trojan", "trojan://\(e(u.pass))@\(str("trojan", "domain")):\(port("trojan"))?security=tls&sni=\(str("trojan", "domain"))&type=tcp\(frag("Trojan"))")) }
        if has("tuic") { l.append(("TUIC", "tuic://\(u.uuid):\(e(u.pass))@\(str("tuic", "domain")):\(port("tuic"))?congestion_control=bbr&alpn=h3&sni=\(str("tuic", "domain"))\(frag("TUIC"))")) }
        if has("anytls") { l.append(("AnyTLS", "anytls://\(e(u.pass))@\(str("anytls", "domain")):\(port("anytls"))?security=tls&sni=\(str("anytls", "domain"))\(frag("AnyTLS"))")) }
        if has("vless_ws") {
            let d = str("vless_ws", "domain")
            l.append(("VLESS WS", "vless://\(u.uuid)@\(d):\(port("vless_ws"))?encryption=none&security=tls&sni=\(d)&fp=chrome&type=ws&host=\(d)&path=\(e(str("vless_ws", "path")))\(frag("VLESS WS"))"))
        }
        if has("vless_grpc") {
            let d = str("vless_grpc", "domain")
            l.append(("VLESS gRPC", "vless://\(u.uuid)@\(d):\(port("vless_grpc"))?encryption=none&security=tls&sni=\(d)&fp=chrome&alpn=h2&type=grpc&serviceName=\(str("vless_grpc", "service"))\(frag("VLESS gRPC"))"))
        }
        if has("shadowtls") {
            let plugin = "shadow-tls;host=\(shadowTlsSni);password=\(u.pass);version=3"
            l.append(("ShadowTLS", "ss://\(Self.ssMethod):\(e(str("shadowtls", "key") + ":" + u.ssKey))@\(h):\(port("shadowtls"))?plugin=\(e(plugin))\(frag("ShadowTLS"))"))
        }
        if has("socks") { l.append(("SOCKS5", "socks5://\(e(u.name)):\(e(u.pass))@\(h):\(port("socks"))\(frag("SOCKS5"))")) }
        return l
    }

    func telegramLink(host: String, user u: MyUser) -> String? {
        has("socks") ? "tg://socks?server=\(host)&port=\(port("socks"))&user=\(Self.enc(u.name))&pass=\(Self.enc(u.pass))" : nil
    }

    /// TrustTunnel: server by IP, our domain as the TLS name, the pinned self-signed certificate.
    func ttProfile(host: String, user u: MyUser, label: String) -> Server {
        Server(name: "\(label) · TrustTunnel" + (u.name == "me" ? "" : " · \(u.name)"), kind: "tt", server: str("tt", "domain"),
               port: port("tt"), userId: u.name, password: u.pass,
               params: ["addresses": (host.contains(":") ? "[\(host)]" : host) + ":\(port("tt"))", "cert": str("tt", "cert"),
                        "upstream": "http2", "ipv6": "0"])
    }

    /// Servers for the app: Hysteria2 gets the exact certificate instead of "insecure".
    func profiles(host: String, user u: MyUser, label: String) -> [Server] {
        links(host: host, user: u, label: label).compactMap { item in
            if item.title == "TrustTunnel" { var p = ttProfile(host: host, user: u, label: label); p.link = item.link; return p }
            guard var p = try? ShareLinks.parse(item.link) else { return nil }
            if p.kind == "hysteria2", has("hy2") { p.params.removeValue(forKey: "insecure"); p.params["cert"] = str("hy2", "cert") }
            return p
        }
    }
}
