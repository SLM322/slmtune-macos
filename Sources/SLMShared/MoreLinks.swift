import Foundation
#if canImport(Compression)
import Compression
#endif

/// Links for the protocols that run on the extra cores (port of MoreProtocols.cs and ExtraCores.kt):
/// TrustTunnel (tt://), AmneziaWG (wireguard:// with AWG keys, .conf, Amnezia vpn://), mieru, ShadowsocksR, Tor.
enum MoreLinks {
    static let awgKeys = ["jc", "jmin", "jmax", "s1", "s2", "s3", "s4", "h1", "h2", "h3", "h4",
                          "i1", "i2", "i3", "i4", "i5", "j1", "j2", "j3", "itime"]

    static let schemes = ["tt://", "vpn://", "mierus://", "mieru://", "ssr://"]

    static func parse(_ link: String) throws -> Server? {
        let l = link.lowercased()
        if l.hasPrefix("tt://") { return try parseTt(link) }
        if l.hasPrefix("vpn://") { return try parseAmneziaVpn(link) }
        if l.hasPrefix("mierus://") || l.hasPrefix("mieru://") { return parseMieru(link) }
        if l.hasPrefix("ssr://") { return try parseSsr(link) }
        return nil
    }

    /// A WireGuard server with any AmneziaWG obfuscation key becomes "amneziawg" (runs on mihomo).
    static func classifyWireGuard(_ s: Server) -> Server {
        var s = s
        if awgKeys.contains(where: { !s.param($0).isEmpty }) { s.kind = "amneziawg" }
        return s
    }

    // MARK: TrustTunnel

    /// tt://?base64url(TLV): tag and length are QUIC-style varints. Tags: 0 version, 1 hostname, 2 address
    /// (repeated), 3 custom SNI, 4 has IPv6, 5 username, 6 password, 7 skip verification, 8 certificate (DER,
    /// repeated), 9 upstream (1 HTTP/2, 2 HTTP/3), 10 anti-DPI, 11 client random.
    static func parseTt(_ link: String) throws -> Server {
        let (name, body) = ShareLinks.splitFragment(link)
        var b64 = String(body.dropFirst(5)).trimmingCharacters(in: CharacterSet(charactersIn: "? \n"))
        if b64.count > 16 * 1024 { throw LinkError(L("Ссылка слишком длинная.")) }
        b64 = b64.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        b64 += String(repeating: "=", count: (4 - b64.count % 4) % 4)
        guard let data = Data(base64Encoded: b64) else { throw LinkError(L("Ссылка TrustTunnel не читается.")) }
        let bytes = [UInt8](data)
        var i = 0
        func varint() throws -> Int {
            guard i < bytes.count else { throw LinkError(L("Ссылка TrustTunnel обрезана.")) }
            let first = Int(bytes[i])
            let len = 1 << (first >> 6)
            guard i + len <= bytes.count else { throw LinkError(L("Ссылка TrustTunnel обрезана.")) }
            var v = first & 0x3f
            for k in 1..<len { v = (v << 8) | Int(bytes[i + k]) }
            i += len
            return v
        }
        var host = "", user = "", pass = "", sni = "", random = "", upstream = "http2"
        var ipv6 = true, skip = false, antiDpi = false
        var addresses: [String] = [], certs: [Data] = []
        while i < bytes.count {
            let tag = try varint()
            let len = try varint()
            guard i + len <= bytes.count else { throw LinkError(L("Ссылка TrustTunnel обрезана.")) }
            let v = Array(bytes[i..<(i + len)])
            i += len
            let str = String(decoding: v, as: UTF8.self)
            let flag = !v.isEmpty && v[0] != 0
            switch tag {
            case 1: host = str
            case 2: addresses.append(str)
            case 3: sni = str
            case 4: ipv6 = flag
            case 5: user = str
            case 6: pass = str
            case 7: skip = flag
            case 8: certs.append(Data(v))
            case 9: upstream = (!v.isEmpty && v[0] == 2) ? "http3" : "http2"
            case 10: antiDpi = flag
            case 11: random = str
            default: break
            }
        }
        guard !host.isEmpty, !addresses.isEmpty, !user.isEmpty else { throw LinkError(L("В ссылке TrustTunnel нет адреса или логина.")) }
        let pem = certs.map { "-----BEGIN CERTIFICATE-----\n" + $0.base64EncodedString(options: .lineLength64Characters) + "\n-----END CERTIFICATE-----\n" }.joined()
        var params: [String: String] = ["addresses": addresses.joined(separator: "\n"), "upstream": upstream]
        if !sni.isEmpty { params["sni"] = sni }
        if !ipv6 { params["ipv6"] = "0" }
        if skip { params["skip"] = "1" }
        if !pem.isEmpty { params["cert"] = pem }
        if antiDpi { params["antidpi"] = "1" }
        if !random.isEmpty { params["random"] = random }
        let port = Int(addresses[0].components(separatedBy: ":").last ?? "") ?? 443
        return Server(name: name.isEmpty ? host : name, kind: "tt", server: host, port: port,
                      userId: user, password: pass, params: params, link: link)
    }

    // MARK: Amnezia vpn://

    /// Amnezia app share string: vpn://base64url(qCompress(json)); qCompress = 4-byte size + zlib.
    /// The WireGuard/AWG config lives in containers[].awg|wireguard.last_config → "config".
    static func parseAmneziaVpn(_ link: String) throws -> Server {
        let (name, body) = ShareLinks.splitFragment(link)
        var b64 = String(body.dropFirst(6)).trimmingCharacters(in: .whitespacesAndNewlines)
            .replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        b64 += String(repeating: "=", count: (4 - b64.count % 4) % 4)
        guard let raw = Data(base64Encoded: b64) else { throw LinkError(L("Ссылка vpn:// не читается.")) }
        let jsonData = inflateQt(raw) ?? raw // some exports are not compressed
        guard let root = try? JSONSerialization.jsonObject(with: jsonData) as? [String: Any] else {
            throw LinkError(L("Ссылка vpn:// не читается."))
        }
        var conf: String?
        for c in (root["containers"] as? [[String: Any]]) ?? [] {
            for key in ["awg", "wireguard"] {
                guard let last = (c[key] as? [String: Any])?["last_config"] as? String,
                      let o = try? JSONSerialization.jsonObject(with: Data(last.utf8)) as? [String: Any],
                      let text = o["config"] as? String else { continue }
                conf = text
                break
            }
            if conf != nil { break }
        }
        guard let conf else { throw LinkError(L("В ссылке vpn:// нет конфигурации AmneziaWG/WireGuard (поддерживаются только они).")) }
        let desc = (root["description"] as? String) ?? (root["name"] as? String) ?? ""
        guard let s = ShareLinks.parseWireGuardConf(conf, name: name.isEmpty ? (desc.isEmpty ? "Amnezia" : desc) : name) else {
            throw LinkError(L("В конфиге нет PrivateKey, PublicKey или Endpoint."))
        }
        return s
    }

    /// qCompress: 4-byte big-endian size, then a zlib stream (2-byte header, DEFLATE, 4-byte Adler-32).
    static func inflateQt(_ data: Data) -> Data? {
        #if canImport(Compression)
        guard data.count > 8 else { return nil }
        let size = data.prefix(4).reduce(0) { ($0 << 8) | Int($1) }
        guard size > 0, size < 4 << 20 else { return nil }
        let deflate = data.subdata(in: 6..<(data.count - 4))
        var out = Data(count: size)
        let n = out.withUnsafeMutableBytes { dst in
            deflate.withUnsafeBytes { src in
                compression_decode_buffer(dst.bindMemory(to: UInt8.self).baseAddress!, size,
                                          src.bindMemory(to: UInt8.self).baseAddress!, deflate.count, nil, COMPRESSION_ZLIB)
            }
        }
        return n > 0 ? out.prefix(n) : nil
        #else
        return nil
        #endif
    }

    // MARK: mieru, ShadowsocksR

    /// mierus://user:pass@host?port=8964&protocol=TCP&multiplexing=…#name
    static func parseMieru(_ link: String) -> Server {
        let (name, body) = ShareLinks.splitFragment(link)
        let a = ShareLinks.authority(body.components(separatedBy: "://").dropFirst().joined(separator: "://"))
        let user = ShareLinks.dec(a.user)
        let parts = user.split(separator: ":", maxSplits: 1).map(String.init)
        let port = Int((a.query["port"] ?? "").components(separatedBy: "-")[0]) ?? a.port
        return Server(name: name.isEmpty ? "mieru \(a.host)" : name, kind: "mieru", server: a.host, port: port,
                      userId: parts.first ?? "", password: parts.count > 1 ? parts[1] : "", params: a.query, link: link)
    }

    /// ssr://base64(host:port:protocol:method:obfs:base64(pass)/?obfsparam=&protoparam=&remarks=)
    static func parseSsr(_ link: String) throws -> Server {
        guard var dec = ShareLinks.decodeBase64(String(link.dropFirst(6)).trimmingCharacters(in: .whitespacesAndNewlines)) else {
            throw LinkError(L("Неверная ссылка ssr://"))
        }
        var q = ""
        if let r = dec.range(of: "/?") { q = String(dec[r.upperBound...]); dec = String(dec[..<r.lowerBound]) }
        let parts = dec.components(separatedBy: ":")
        let n = parts.count
        guard n >= 6, let port = Int(parts[n - 5]) else { throw LinkError(L("Неверная ссылка ssr://")) }
        var params: [String: String] = ["protocol": parts[n - 4], "obfs": parts[n - 2]]
        for (k, v) in ShareLinks.parseQuery(q) { params[k] = ShareLinks.decodeBase64(v) ?? v }
        let host = parts[0..<(n - 5)].joined(separator: ":").trimmingCharacters(in: CharacterSet(charactersIn: "[]"))
        let remarks = params["remarks"] ?? ""
        return Server(name: remarks.isEmpty ? "ssr \(host)" : remarks, kind: "ssr", server: host, port: port,
                      userId: parts[n - 3], password: ShareLinks.decodeBase64(parts[n - 1]) ?? "", params: params, link: link)
    }

    // MARK: Tor

    static let torTransports: [(id: String, title: String)] = [
        ("snowflake", "Snowflake — через WebRTC-волонтёров, работает почти везде"),
        ("webtunnel", "WebTunnel — выглядит как обычный HTTPS-сайт (мосты из @GetBridgesBot)"),
        ("obfs4", "obfs4 — случайный шум, встроенные мосты"),
        ("meek", "meek — через CDN, медленно, но надёжно"),
        ("none", "Без мостов — если Tor у провайдера не заблокирован"),
        ("custom", "Свои мосты (с bridges.torproject.org или из @GetBridgesBot)"),
    ]

    static func torProfile(transport: String, bridges: String = "") -> Server {
        let title = torTransports.first { $0.id == transport }.map { $0.title.components(separatedBy: " ")[0] } ?? transport
        return Server(name: "Tor · " + title, kind: "tor", server: "tor", port: 9050,
                      params: ["transport": transport, "bridges": bridges.replacingOccurrences(of: "\r", with: "").trimmingCharacters(in: .whitespacesAndNewlines)])
    }

    // MARK: export

    /// The reverse of parseTt, for "Поделиться".
    static func ttLink(_ s: Server) -> String {
        var out: [UInt8] = []
        func varint(_ v: Int) {
            if v < 0x40 { out.append(UInt8(v)) }
            else if v < 0x4000 { out += [UInt8(0x40 | (v >> 8)), UInt8(v & 0xff)] }
            else { out += [UInt8(0x80 | (v >> 24)), UInt8((v >> 16) & 0xff), UInt8((v >> 8) & 0xff), UInt8(v & 0xff)] }
        }
        func put(_ tag: Int, _ v: [UInt8]) { varint(tag); varint(v.count); out += v }
        func str(_ tag: Int, _ v: String) { put(tag, Array(v.utf8)) }
        put(0, [1]); str(1, s.server); str(5, s.userId); str(6, s.password)
        for a in s.param("addresses").components(separatedBy: "\n") where !a.trimmingCharacters(in: .whitespaces).isEmpty {
            str(2, a.trimmingCharacters(in: .whitespaces))
        }
        if !s.param("sni").isEmpty { str(3, s.param("sni")) }
        if s.param("ipv6") == "0" { put(4, [0]) }
        if s.param("skip") == "1" { put(7, [1]) }
        for der in pemCertificates(s.param("cert")) { put(8, [UInt8](der)) }
        if s.param("upstream") == "http3" { put(9, [2]) }
        if s.param("antidpi") == "1" { put(10, [1]) }
        if !s.param("random").isEmpty { str(11, s.param("random")) }
        let b64 = Data(out).base64EncodedString().replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
        let name = s.name.isEmpty || s.name == s.server ? "" : "#" + (s.name.addingPercentEncoding(withAllowedCharacters: .urlFragmentAllowed) ?? "")
        return "tt://?" + b64 + name
    }

    static func pemCertificates(_ pem: String) -> [Data] {
        pem.components(separatedBy: "-----BEGIN CERTIFICATE-----").dropFirst().compactMap { part in
            let body = part.components(separatedBy: "-----END CERTIFICATE-----")[0]
            return Data(base64Encoded: body, options: .ignoreUnknownCharacters)
        }
    }
}
