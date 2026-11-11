import Foundation

/// Localized string (Russian text is the key, as Loc.T in the Windows version; en.lproj has the translations).
func L(_ key: String) -> String { NSLocalizedString(key, comment: "") }
func L(_ key: String, _ args: CVarArg...) -> String { String(format: NSLocalizedString(key, comment: ""), arguments: args) }

struct LinkError: LocalizedError {
    let message: String
    init(_ m: String) { message = m }
    var errorDescription: String? { message }
}

/// Share links → servers. Same formats as the Windows/Android versions: vless, vmess, trojan, ss (incl. the
/// shadow-tls plugin), hysteria2/hy2, hysteria, tuic, anytls, naive+https/naive+quic, socks, wireguard.
enum ShareLinks {
    static let schemes = [
        "vless://", "vmess://", "trojan://", "ss://", "hysteria2://", "hy2://", "hysteria://", "tuic://", "anytls://",
        "naive+https://", "naive+quic://", "socks5://", "socks://", "wireguard://", "wg://",
    ]

    static func isSupported(_ link: String) -> Bool {
        let l = link.lowercased()
        return schemes.contains { l.hasPrefix($0) } || MoreLinks.schemes.contains { l.hasPrefix($0) }
    }

    /// Every link in a text (one per line or separated by spaces), and base64 subscription bodies.
    static func findLinks(_ text: String) -> [String] {
        var t = text.trimmingCharacters(in: .whitespacesAndNewlines)
        let lower = t.lowercased()
        if !(schemes + MoreLinks.schemes).contains(where: { lower.contains($0) }),
           let decoded = decodeBase64(t.replacingOccurrences(of: "\n", with: "").replacingOccurrences(of: "\r", with: "")) {
            t = decoded
        }
        var seen = Set<String>()
        return t.components(separatedBy: CharacterSet(charactersIn: "\r\n \t"))
            .map { $0.trimmingCharacters(in: CharacterSet(charactersIn: "\"',;")) }
            .filter { isSupported($0) && seen.insert($0).inserted }
    }

    static func decodeBase64(_ s: String) -> String? {
        var clean = s.trimmingCharacters(in: .whitespacesAndNewlines)
            .replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        clean += String(repeating: "=", count: (4 - clean.count % 4) % 4)
        guard let data = Data(base64Encoded: clean, options: .ignoreUnknownCharacters),
              let str = String(data: data, encoding: .utf8), !str.isEmpty,
              str.unicodeScalars.allSatisfy({ $0.value >= 9 }) else { return nil }
        return str
    }

    static func dec(_ s: String) -> String { s.removingPercentEncoding ?? s }

    static func parseQuery(_ q: String) -> [String: String] {
        var d: [String: String] = [:]
        for pair in q.split(separator: "&") where !pair.isEmpty {
            let p = String(pair)
            if let i = p.firstIndex(of: "=") {
                let k = dec(String(p[..<i])), v = dec(String(p[p.index(after: i)...]))
                if !k.isEmpty, k.count < 64, v.count < 4096 { d[k] = v }
            } else { d[dec(p)] = "" }
        }
        return d
    }

    static func splitFragment(_ link: String) -> (name: String, body: String) {
        guard let h = link.firstIndex(of: "#") else { return ("", link) }
        return (dec(String(link[link.index(after: h)...])).trimmingCharacters(in: .whitespaces), String(link[..<h]))
    }

    /// "user@host:port/path?query" (no scheme) → parts. Tolerant to unencoded characters, unlike URLComponents.
    struct Authority { var user = ""; var host = ""; var port = 0; var query: [String: String] = [:] }

    static func authority(_ rest: String) -> Authority {
        var a = Authority()
        var s = rest
        if let q = s.firstIndex(of: "?") { a.query = parseQuery(String(s[s.index(after: q)...])); s = String(s[..<q]) }
        // User info first: a password may contain "/" (base64), the path only follows the host.
        if let at = s.lastIndex(of: "@") { a.user = String(s[..<at]); s = String(s[s.index(after: at)...]) }
        if let slash = s.firstIndex(of: "/") { s = String(s[..<slash]) }
        if s.hasPrefix("["), let close = s.firstIndex(of: "]") {
            a.host = String(s[s.index(after: s.startIndex)..<close])
            let after = s[s.index(after: close)...]
            if after.hasPrefix(":") { a.port = Int(after.dropFirst()) ?? 0 }
        } else if let colon = s.lastIndex(of: ":"), s.filter({ $0 == ":" }).count == 1 {
            a.host = String(s[..<colon]); a.port = Int(s[s.index(after: colon)...]) ?? 0
        } else {
            a.host = s
        }
        return a
    }

    static func parse(_ raw: String) throws -> Server {
        let link = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        if link.count > 8192 { throw LinkError(L("Ссылка слишком длинная.")) }
        let lower = link.lowercased()
        var s: Server
        if let more = try MoreLinks.parse(link) { s = more }
        else if lower.hasPrefix("vmess://") { s = try parseVmess(link) }
        else if lower.hasPrefix("ss://") { s = try parseShadowsocks(link) }
        else if lower.hasPrefix("socks5://") || lower.hasPrefix("socks://") { s = parseSocks(link) }
        else if lower.hasPrefix("wireguard://") || lower.hasPrefix("wg://") { s = parseWireGuard(link) }
        else { s = try parseGeneric(link) }
        if s.kind == "wireguard" { s = MoreLinks.classifyWireGuard(s) }
        try validate(s)
        return s
    }

    private static func parseGeneric(_ original: String) throws -> Server {
        let lower = original.lowercased()
        var kind: String
        var rest: String
        var quic = false
        if lower.hasPrefix("hy2://") { kind = "hysteria2"; rest = String(original.dropFirst(6)) }
        else if lower.hasPrefix("naive+https://") { kind = "naive"; rest = String(original.dropFirst(14)) }
        else if lower.hasPrefix("naive+quic://") { kind = "naive"; quic = true; rest = String(original.dropFirst(13)) }
        else if let r = original.range(of: "://") { kind = String(original[..<r.lowerBound]).lowercased(); rest = String(original[r.upperBound...]) }
        else { throw LinkError(L("Ссылка не распознана.")) }
        let (name, body) = splitFragment(rest)
        let a = authority(body)
        var params = a.query
        if quic { params["quic"] = "1" }
        let user = dec(a.user)
        var userId = "", password = ""
        switch kind {
        case "vless": userId = user
        case "tuic", "naive":
            if let c = user.firstIndex(of: ":") { userId = String(user[..<c]); password = String(user[user.index(after: c)...]) }
            else { userId = user }
        case "trojan", "hysteria2", "anytls": password = user
        case "hysteria": password = params["auth"] ?? user
        default: throw LinkError(L("Неизвестный протокол: %@", kind))
        }
        return Server(name: name.isEmpty ? "\(kind) \(a.host)" : name, kind: kind, server: a.host,
                      port: a.port > 0 ? a.port : 443, userId: userId, password: password, params: params, link: original)
    }

    static func needsXray(_ params: [String: String]) -> Bool {
        let net = (params["type"] ?? "").lowercased()
        let enc = (params["encryption"] ?? "none").lowercased()
        return net == "xhttp" || net == "splithttp" || (!enc.isEmpty && enc != "none")
    }

    /// vmess://base64({"v":"2","ps":"name","add":"host","port":"443","id":"uuid","net":"ws",...})
    private static func parseVmess(_ link: String) throws -> Server {
        let b64 = String(link.dropFirst(8)).components(separatedBy: "#")[0]
        guard let js = decodeBase64(b64), let data = js.data(using: .utf8),
              let o = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw LinkError(L("Ссылка VMess не читается."))
        }
        func f(_ k: String) -> String {
            if let s = o[k] as? String { return s }
            if let n = o[k] as? NSNumber { return n.stringValue }
            return ""
        }
        var params: [String: String] = [
            "type": f("net").isEmpty ? "tcp" : f("net"), "security": f("tls"), "sni": f("sni"),
            "host": f("host"), "path": f("path"), "aid": f("aid"), "scy": f("scy").isEmpty ? "auto" : f("scy"),
            "fp": f("fp"), "alpn": f("alpn"),
        ].filter { !$0.value.isEmpty }
        if params["type"] == "grpc", !f("path").isEmpty { params["serviceName"] = f("path") }
        return Server(name: f("ps").isEmpty ? "vmess \(f("add"))" : f("ps"), kind: "vmess", server: f("add"),
                      port: Int(f("port")) ?? 443, userId: f("id"), params: params, link: link)
    }

    /// SIP002 ss://base64(method:pass)@host:port, plain ss://method:pass@host:port and legacy ss://base64(all).
    private static func parseShadowsocks(_ link: String) throws -> Server {
        let (name, body0) = splitFragment(link)
        var body = String(body0.dropFirst(5))
        if !body.contains("@") {
            let main = body.components(separatedBy: "?")[0].components(separatedBy: "/")[0]
            if let d = decodeBase64(main) {
                body = d + (body.contains("?") ? "?" + body.components(separatedBy: "?").dropFirst().joined(separator: "?") : "")
            }
        }
        guard let at = body.lastIndex(of: "@") else { throw LinkError(L("Ссылка Shadowsocks не читается.")) }
        var info = dec(String(body[..<at]))
        if !info.contains(":"), let d = decodeBase64(info) { info = d }
        guard let colon = info.firstIndex(of: ":") else { throw LinkError(L("Ссылка Shadowsocks не читается.")) }
        let a = authority(String(body[body.index(after: at)...]))
        return Server(name: name.isEmpty ? "ss \(a.host)" : name, kind: "ss", server: a.host, port: a.port > 0 ? a.port : 8388,
                      userId: String(info[..<colon]), password: String(info[info.index(after: colon)...]), params: a.query, link: link)
    }

    private static func parseSocks(_ link: String) -> Server {
        let (name, body) = splitFragment(link)
        let a = authority(body.components(separatedBy: "://").dropFirst().joined(separator: "://"))
        var info = dec(a.user)
        if !info.isEmpty, !info.contains(":"), let d = decodeBase64(info), d.contains(":") { info = d }
        let parts = info.split(separator: ":", maxSplits: 1).map(String.init)
        return Server(name: name.isEmpty ? "socks \(a.host)" : name, kind: "socks", server: a.host, port: a.port > 0 ? a.port : 1080,
                      userId: parts.first ?? "", password: parts.count > 1 ? parts[1] : "", link: link)
    }

    /// v2rayN style: wireguard://PRIVATEKEY@host:port?publickey=&address=&mtu=&reserved=#name
    private static func parseWireGuard(_ link: String) -> Server {
        let (name, body) = splitFragment(link)
        let a = authority(body.components(separatedBy: "://").dropFirst().joined(separator: "://"))
        return Server(name: name.isEmpty ? "WireGuard \(a.host)" : name, kind: "wireguard", server: a.host,
                      port: a.port > 0 ? a.port : 51820, password: dec(a.user), params: a.query, link: link)
    }

    /// A WireGuard .conf ([Interface] / [Peer]) → server. Returns nil if the text isn't one.
    static func parseWireGuardConf(_ text: String, name: String = "") -> Server? {
        guard text.contains("[Interface]"), text.contains("[Peer]") else { return nil }
        var iface: [String: String] = [:], peer: [String: String] = [:]
        var section = ""
        for raw in text.components(separatedBy: .newlines) {
            let line = raw.components(separatedBy: "#")[0].trimmingCharacters(in: .whitespaces)
            if line.hasPrefix("[") { section = line.lowercased(); continue }
            guard let eq = line.firstIndex(of: "=") else { continue }
            let k = line[..<eq].trimmingCharacters(in: .whitespaces).lowercased()
            let v = line[line.index(after: eq)...].trimmingCharacters(in: .whitespaces)
            if section == "[interface]" { iface[k] = v } else if section == "[peer]", peer[k] == nil { peer[k] = v }
        }
        guard let pk = iface["privatekey"], let endpoint = peer["endpoint"], let pub = peer["publickey"] else { return nil }
        let a = authority(endpoint)
        var params: [String: String] = ["publickey": pub, "address": iface["address"] ?? ""]
        if let m = iface["mtu"] { params["mtu"] = m }
        if let p = peer["presharedkey"] { params["presharedkey"] = p }
        if let ips = peer["allowedips"] { params["allowedips"] = ips }
        if let k = peer["persistentkeepalive"] { params["keepalive"] = k }
        for key in MoreLinks.awgKeys { if let v = iface[key] { params[key] = v } }
        return MoreLinks.classifyWireGuard(Server(name: name.isEmpty ? "WireGuard \(a.host)" : name, kind: "wireguard", server: a.host,
                      port: a.port > 0 ? a.port : 51820, password: pk, params: params))
    }

    static func validate(_ s: Server) throws {
        if s.server.trimmingCharacters(in: .whitespaces).isEmpty { throw LinkError(L("В ссылке нет адреса сервера.")) }
        if !(1...65535).contains(s.port) { throw LinkError(L("Неверный порт.")) }
        if ["vless", "vmess", "tuic"].contains(s.kind), UUID(uuidString: s.userId) == nil {
            throw LinkError(L("В ссылке нет корректного UUID."))
        }
        if ["trojan", "hysteria2", "anytls", "ss", "tuic"].contains(s.kind), s.password.isEmpty {
            throw LinkError(L("В ссылке нет пароля."))
        }
        if ["wireguard", "amneziawg"].contains(s.kind), s.password.isEmpty || s.param("publickey").isEmpty {
            throw LinkError(L("В ссылке WireGuard нет ключей."))
        }
    }

    static func describe(_ s: Server) -> String {
        let name: String
        switch s.kind {
        case "vless": name = "VLESS"
        case "vmess": name = "VMess"
        case "trojan": name = "Trojan"
        case "ss": name = "Shadowsocks"
        case "hysteria2": name = "Hysteria2"
        case "hysteria": name = "Hysteria"
        case "tuic": name = "TUIC"
        case "anytls": name = "AnyTLS"
        case "naive": name = "NaiveProxy"
        case "socks": name = "SOCKS5"
        case "wireguard": name = s.param("warp") == "1" ? "Cloudflare WARP" : "WireGuard"
        case "amneziawg": name = "AmneziaWG"
        case "mieru": name = "mieru"
        case "ssr": name = "ShadowsocksR"
        case "tt": return "TrustTunnel · " + (s.param("upstream") == "http3" ? "HTTP/3" : "HTTP/2")
        case "tor": return "Tor · " + s.param("transport", "snowflake")
        case "group":
            return L("Группа") + " · " + (s.param("mode") == "fallback" ? L("резерв") : L("самый быстрый")) + " · \(s.members.count)"
        default: name = s.kind
        }
        var parts = [name]
        let net = s.param("type")
        if !net.isEmpty, net != "tcp", net != "raw" { parts.append(net) }
        if s.param("security") == "reality" { parts.append("Reality") }
        if s.kind == "naive", s.param("quic") == "1" { parts.append("QUIC") }
        if s.kind == "ss", s.param("plugin").lowercased().hasPrefix("shadow-tls") { parts.append("ShadowTLS") }
        if s.kind == "vless", s.param("encryption", "none") != "none" { parts.append("Encryption") }
        if let e = Engines.engine(s), e != .trusttunnel, e != .tor { parts.append("(\(e.title))") }
        return parts.joined(separator: " · ")
    }

    /// Whether the protocol carries UDP (calls, games, QUIC).
    static func hasUdp(_ s: Server) -> Bool {
        !["naive", "socks", "tor"].contains(s.kind) && !(s.kind == "ss" && s.param("plugin").lowercased().hasPrefix("shadow-tls"))
    }

    // ---- export (the "Поделиться" button and QR) ----

    /// The original link when there is one, otherwise a rebuilt one for the common kinds.
    static func export(_ s: Server) -> String? {
        if !s.link.isEmpty { return s.link }
        let frag = "#" + (s.title.addingPercentEncoding(withAllowedCharacters: .urlFragmentAllowed) ?? "")
        let q = s.params.sorted { $0.key < $1.key }
            .map { "\($0.key)=\($0.value.addingPercentEncoding(withAllowedCharacters: .urlQueryValueAllowed) ?? "")" }
            .joined(separator: "&")
        let host = s.server.contains(":") ? "[\(s.server)]" : s.server
        let enc = { (v: String) in v.addingPercentEncoding(withAllowedCharacters: .urlUserAllowed) ?? v }
        switch s.kind {
        case "vless": return "vless://\(enc(s.userId))@\(host):\(s.port)?\(q)\(frag)"
        case "vmess":
            let o: [String: String] = [
                "v": "2", "ps": s.title, "add": s.server, "port": "\(s.port)", "id": s.userId,
                "aid": s.param("aid", "0"), "scy": s.param("scy", "auto"), "net": s.param("type", "tcp"),
                "host": s.param("host"), "path": s.param("serviceName", s.param("path")), "tls": s.param("security"),
                "sni": s.param("sni"), "alpn": s.param("alpn"), "fp": s.param("fp"),
            ]
            guard let d = try? JSONSerialization.data(withJSONObject: o, options: [.sortedKeys]) else { return nil }
            return "vmess://" + d.base64EncodedString()
        case "trojan", "hysteria2", "anytls": return "\(s.kind)://\(enc(s.password))@\(host):\(s.port)?\(q)\(frag)"
        case "tuic": return "tuic://\(enc(s.userId)):\(enc(s.password))@\(host):\(s.port)?\(q)\(frag)"
        case "ss":
            let ui = Data("\(s.userId):\(s.password)".utf8).base64EncodedString()
            return "ss://\(ui)@\(host):\(s.port)\(q.isEmpty ? "" : "?" + q)\(frag)"
        case "wireguard", "amneziawg": return "wireguard://\(enc(s.password))@\(host):\(s.port)?\(q)\(frag)"
        case "tt": return MoreLinks.ttLink(s)
        default: return nil
        }
    }
}

extension CharacterSet {
    static let urlQueryValueAllowed: CharacterSet = {
        var c = CharacterSet.urlQueryAllowed
        c.remove(charactersIn: "&=+#")
        return c
    }()
}
