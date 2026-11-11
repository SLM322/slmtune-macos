import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

/// Lists behind the presets and blocking — the same sources as the Windows and Android versions:
/// - blocked in Russia (itdoginfo/allow-domains) — "only blocked sites through the VPN";
/// - Russian sites (v2fly category-ru) and Russian IPs (ipverse) — "everything except Russia";
/// - MetaCubeX rule sets (.srs) for ads, trackers, 18+.
/// The app downloads them into the App Group; sing-box in the extension reads them as local files,
/// so a failed download never stops a connection (the rule is just left out).
enum Lists {
    static let blocked = "ru-blocked"
    static let ruDomains = "ru-domains"
    static let ruIps = "ru-ips"

    static let sources: [String: String] = [
        blocked: "https://raw.githubusercontent.com/itdoginfo/allow-domains/main/Russia/inside-raw.lst",
        ruDomains: "https://raw.githubusercontent.com/v2fly/domain-list-community/master/data/category-ru",
        ruIps: "https://raw.githubusercontent.com/ipverse/rir-ip/master/country/ru/ipv4-aggregated.txt",
    ]

    struct Block: Identifiable, Hashable {
        let id: String
        let title: String
        let note: String
        let file: String
    }

    static let blocks: [Block] = [
        Block(id: "ads", title: "Реклама", note: "баннеры, всплывающие окна, рекламные сети", file: "category-ads-all.srs"),
        Block(id: "trackers", title: "Трекеры и аналитика", note: "счётчики и слежка за посещениями", file: "tracker.srs"),
        Block(id: "winspy", title: "Телеметрия Windows", note: "для виртуальных машин с Windows на этом Mac", file: "win-spy.srs"),
        Block(id: "adult", title: "Сайты 18+", note: "семейный фильтр", file: "category-porn.srs"),
    ]
    static let blockBase = "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/"

    static func ruleFile(_ id: String) -> URL { AppGroup.rulesDir.appendingPathComponent("\(id).json") }
    static func blockFile(_ b: Block) -> URL { AppGroup.rulesDir.appendingPathComponent(b.file) }

    static func has(_ url: URL) -> Bool {
        let size = (try? FileManager.default.attributesOfItem(atPath: url.path))?[.size] as? NSNumber
        return (size?.intValue ?? 0) > 0
    }

    static func presetLists(_ p: Preset) -> [String] {
        switch p {
        case .blocked: return [blocked]
        case .exceptRu: return [ruDomains, ruIps]
        case .all: return []
        }
    }

    /// Downloads what the settings need and is missing or older than a day. Returns how many were updated.
    @discardableResult
    static func update(_ s: AppSettings, force: Bool = false) async -> Int {
        var n = 0
        for id in presetLists(s.preset) {
            let f = ruleFile(id)
            if !force, fresh(f) { continue }
            guard let url = URL(string: sources[id]!), let text = try? await fetchText(url) else { continue }
            let lines = text.components(separatedBy: .newlines).map { $0.trimmingCharacters(in: .whitespaces) }
                .filter { !$0.isEmpty && !$0.hasPrefix("#") }
            let json: String
            switch id {
            case ruIps: json = ruleSet(ips: lines)
            case ruDomains: json = v2flyRuleSet(text)
            default: json = ruleSet(suffixes: lines.map { $0.hasPrefix(".") ? String($0.dropFirst()) : $0 })
            }
            if (try? Data(json.utf8).write(to: f, options: .atomic)) != nil { n += 1 }
        }
        for b in blocks where s.blockLists.contains(b.id) {
            let f = blockFile(b)
            if !force, fresh(f) { continue }
            guard let url = URL(string: blockBase + b.file),
                  let r = try? await session.data(from: url),
                  (r.1 as? HTTPURLResponse)?.statusCode == 200,
                  r.0.count > 3, r.0.prefix(3) == Data("SRS".utf8) else { continue }
            let data = r.0
            if (try? data.write(to: f, options: .atomic)) != nil { n += 1 }
        }
        return n
    }

    private static func fresh(_ f: URL) -> Bool {
        guard has(f), let m = (try? FileManager.default.attributesOfItem(atPath: f.path))?[.modificationDate] as? Date else { return false }
        return Date().timeIntervalSince(m) < 86_400
    }

    static let session: URLSession = {
        let c = URLSessionConfiguration.ephemeral
        c.timeoutIntervalForRequest = 20
        c.timeoutIntervalForResource = 60
        c.httpAdditionalHeaders = ["User-Agent": "SLMtune-iOS/4.1"]
        return URLSession(configuration: c)
    }()

    static func fetchText(_ url: URL) async throws -> String {
        let (data, resp) = try await session.data(from: url)
        guard let http = resp as? HTTPURLResponse, (200..<300).contains(http.statusCode) else {
            throw LinkError("HTTP \((resp as? HTTPURLResponse)?.statusCode ?? 0)")
        }
        return String(decoding: data, as: UTF8.self)
    }

    static func ruleSet(suffixes: [String] = [], domains: [String] = [], ips: [String] = []) -> String {
        var rule: [String: Any] = [:]
        if !suffixes.isEmpty { rule["domain_suffix"] = Array(NSOrderedSet(array: suffixes)) }
        if !domains.isEmpty { rule["domain"] = Array(NSOrderedSet(array: domains)) }
        if !ips.isEmpty { rule["ip_cidr"] = Array(NSOrderedSet(array: ips)) }
        let doc: [String: Any] = ["version": 3, "rules": [rule]]
        let data = (try? JSONSerialization.data(withJSONObject: doc)) ?? Data()
        return String(decoding: data, as: UTF8.self)
    }

    /// v2fly format: "domain", "full:x", "domain:x"; "regexp:/keyword:/include:" skipped, "@attr" stripped.
    static func v2flyRuleSet(_ text: String) -> String {
        var suffixes: [String] = [], full: [String] = []
        for raw in text.components(separatedBy: .newlines) {
            var line = raw.components(separatedBy: "#")[0].trimmingCharacters(in: .whitespaces)
            line = line.components(separatedBy: " ")[0].components(separatedBy: "@")[0].trimmingCharacters(in: .whitespaces)
            if line.isEmpty { continue }
            if line.hasPrefix("full:") { full.append(String(line.dropFirst(5))) }
            else if line.hasPrefix("domain:") { suffixes.append(String(line.dropFirst(7))) }
            else if line.contains(":") { continue }
            else { suffixes.append(line) }
        }
        suffixes += ["ru", "xn--p1ai", "su"] // .ru, .рф, .su
        return ruleSet(suffixes: suffixes, domains: full)
    }
}
