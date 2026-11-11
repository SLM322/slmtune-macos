import Foundation
@testable import SLMShared

/// One entry point for the clipboard, QR codes, slmtune:// links, files and text shared from other apps.
enum Importer {
    enum Result {
        case servers([Server], failed: [String])
        case subscription(String)
        case nothing(String)
    }

    static func parse(_ raw: String) -> Result {
        var text = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        if text.lowercased().hasPrefix("slmtune://") {
            guard let t = fromDeepLink(text) else { return .nothing(L("Ссылка slmtune:// не распознана.")) }
            text = t
        }
        if (text.hasPrefix("https://") || text.hasPrefix("http://")), !text.contains("\n"), !text.contains(" ") {
            return .subscription(text)
        }
        if let wg = ShareLinks.parseWireGuardConf(text) { return .servers([wg], failed: []) }
        let links = ShareLinks.findLinks(text)
        if links.isEmpty {
            return .nothing(L("Нет поддерживаемых ссылок: vless://, vmess://, trojan://, ss://, hysteria2://, tuic://, anytls://, naive+https://, wireguard:// или ссылки на подписку."))
        }
        var ok: [Server] = [], failed: [String] = []
        for l in links {
            do { ok.append(try ShareLinks.parse(l)) } catch { failed.append(error.localizedDescription) }
        }
        return .servers(ok, failed: failed)
    }

    /// slmtune://import?link=…, slmtune://subscribe?url=…, or a share link right after the scheme.
    static func fromDeepLink(_ link: String) -> String? {
        let rest = String(link.dropFirst("slmtune://".count))
        if !ShareLinks.findLinks(rest).isEmpty { return rest }
        guard let c = URLComponents(string: link) else { return nil }
        let q = { (name: String) in c.queryItems?.first { $0.name == name }?.value }
        switch c.host?.lowercased() {
        case "import", "add":
            guard let l = q("link") ?? q("url") else { return nil }
            return ShareLinks.findLinks(l).isEmpty ? (ShareLinks.decodeBase64(l) ?? l) : l
        case "subscribe", "sub", "install-config":
            guard let u = q("url"), u.hasPrefix("https://") || u.hasPrefix("http://") else { return nil }
            return u
        default:
            return nil
        }
    }
}

/// Provider subscriptions: the server list plus traffic left and the end date (subscription-userinfo).
enum Subscriptions {
    struct Fetched { let servers: [Server]; let skipped: Int; let sub: Subscription }

    static func fetch(_ sub: Subscription) async throws -> Fetched {
        guard let url = URL(string: sub.url), ["https", "http"].contains(url.scheme?.lowercased() ?? "") else {
            throw LinkError(L("Адрес подписки должен начинаться с https://"))
        }
        var req = URLRequest(url: url, timeoutInterval: 20)
        // Panels (Marzban, 3x-ui, Remnawave) answer v2rayN-like clients with the plain link list.
        req.setValue("v2rayN/7.0 SLMtune-macOS/4.1", forHTTPHeaderField: "User-Agent")
        let (data, resp) = try await URLSession.shared.data(for: req)
        guard let http = resp as? HTTPURLResponse, (200..<300).contains(http.statusCode) else {
            throw LinkError("HTTP \((resp as? HTTPURLResponse)?.statusCode ?? 0)")
        }
        var updated = sub
        updated.lastUpdate = Date()
        updated.lastError = nil
        if let info = http.value(forHTTPHeaderField: "subscription-userinfo") { applyUserInfo(&updated, info) }
        if updated.name.isEmpty, let t = http.value(forHTTPHeaderField: "profile-title") {
            let title = t.lowercased().hasPrefix("base64:") ? (ShareLinks.decodeBase64(String(t.dropFirst(7))) ?? t) : t
            updated.name = title.trimmingCharacters(in: .whitespaces)
        }
        let links = ShareLinks.findLinks(String(decoding: data, as: UTF8.self))
        guard !links.isEmpty else { throw LinkError(L("В ответе подписки нет поддерживаемых ссылок.")) }
        var skipped = 0
        let servers: [Server] = links.compactMap { l in
            guard var s = try? ShareLinks.parse(l) else { skipped += 1; return nil }
            s.subscriptionId = sub.id
            return s
        }
        updated.count = servers.count
        if updated.name.isEmpty { updated.name = url.host ?? L("Подписка") }
        return Fetched(servers: servers, skipped: skipped, sub: updated)
    }

    /// "upload=1; download=2; total=3; expire=1767139200"
    static func applyUserInfo(_ s: inout Subscription, _ header: String) {
        for part in header.split(separator: ";") {
            let kv = part.split(separator: "=", maxSplits: 1).map { $0.trimmingCharacters(in: .whitespaces) }
            guard kv.count == 2, let v = Double(kv[1]) else { continue }
            switch kv[0].lowercased() {
            case "upload": s.upload = Int64(v)
            case "download": s.download = Int64(v)
            case "total": s.total = Int64(v)
            case "expire": s.expire = Int64(v)
            default: break
            }
        }
    }

    /// "38,2 из 100 ГБ · до 30.11.2026" or "".
    static func describe(_ s: Subscription) -> String {
        if s.total <= 0 && s.expire <= 0 { return "" }
        let f = NumberFormatter()
        f.maximumFractionDigits = 1
        f.minimumFractionDigits = 0
        let gb = { (b: Int64) in f.string(from: NSNumber(value: Double(b) / 1_073_741_824)) ?? "0" }
        var parts: [String] = []
        parts.append(s.total > 0 ? L("%@ из %@ ГБ", gb(s.upload + s.download), gb(s.total))
                                 : L("%@ ГБ, без лимита", gb(s.upload + s.download)))
        if s.expire > 0 {
            let d = Date(timeIntervalSince1970: TimeInterval(s.expire))
            let date = d.formatted(date: .numeric, time: .omitted)
            parts.append(d < Date() ? L("истекла %@", date) : L("до %@", date))
        }
        return parts.joined(separator: " · ")
    }
}
