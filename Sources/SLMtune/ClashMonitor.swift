import Foundation
@testable import SLMShared

/// Speed, connections and traffic per program from sing-box's Clash API (127.0.0.1, with a secret).
/// Works in every mode (TUN and proxy), read once a second while connected.
@MainActor
final class ClashMonitor: ObservableObject {
    struct Conn: Identifiable, Hashable {
        let id: String
        let host: String
        let network: String
        let chain: String
        let rule: String
        let process: String
        let up: Int64
        let down: Int64
        let start: Date?
        var viaVpn: Bool { chain != "direct" && chain != "zapret" && !chain.isEmpty }
    }

    @Published private(set) var down: Int64 = 0
    @Published private(set) var up: Int64 = 0
    @Published private(set) var totalDown: Int64 = 0
    @Published private(set) var totalUp: Int64 = 0
    @Published private(set) var connections: [Conn] = []
    /// The last 120 seconds of (down, up) per second, for the graph.
    @Published private(set) var history: [(down: Int64, up: Int64)] = []

    private var timer: Timer?
    private var lastTotals: (Int64, Int64)?
    /// Bytes each connection had at the previous reading (for traffic per program).
    private var seen: [String: (Int64, Int64)] = [:]
    let usage = MonthlyUsage()

    func run(_ on: Bool) {
        timer?.invalidate()
        timer = nil
        lastTotals = nil
        seen = [:]
        down = 0; up = 0; totalDown = 0; totalUp = 0
        connections = []
        history = []
        usage.save()
        guard on else { return }
        timer = Timer.scheduledTimer(withTimeInterval: 1, repeats: true) { [weak self] _ in
            Task { @MainActor in await self?.tick() }
        }
    }

    private static func request(_ path: String, method: String = "GET") -> URLRequest {
        var r = URLRequest(url: URL(string: "http://127.0.0.1:\(AppGroup.clashPort)\(path)")!, timeoutInterval: 2)
        r.httpMethod = method
        r.setValue("Bearer \(AppGroup.clashSecret)", forHTTPHeaderField: "Authorization")
        return r
    }

    private func tick() async {
        guard let (data, _) = try? await URLSession.shared.data(for: Self.request("/connections")),
              let root = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { return }
        let td = (root["downloadTotal"] as? NSNumber)?.int64Value ?? 0
        let tu = (root["uploadTotal"] as? NSNumber)?.int64Value ?? 0
        if let last = lastTotals { down = max(0, td - last.0); up = max(0, tu - last.1) }
        lastTotals = (td, tu)
        totalDown = td; totalUp = tu
        history.append((down, up))
        if history.count > 120 { history.removeFirst(history.count - 120) }

        var list: [Conn] = []
        var alive = Set<String>()
        for c in root["connections"] as? [[String: Any]] ?? [] {
            let m = c["metadata"] as? [String: Any] ?? [:]
            let id = c["id"] as? String ?? UUID().uuidString
            let host = (m["host"] as? String).flatMap { $0.isEmpty ? nil : $0 } ?? "\(m["destinationIP"] as? String ?? ""):\(m["destinationPort"] as? String ?? "")"
            let chains = c["chains"] as? [String] ?? []
            let path = m["processPath"] as? String ?? ""
            let process = path.isEmpty ? "" : (path as NSString).lastPathComponent
            let cu = (c["upload"] as? NSNumber)?.int64Value ?? 0
            let cd = (c["download"] as? NSNumber)?.int64Value ?? 0
            let start = (c["start"] as? String).flatMap { ISO8601DateFormatter().date(from: $0) }
            let conn = Conn(id: id, host: host, network: m["network"] as? String ?? "", chain: chains.first ?? "",
                            rule: c["rule"] as? String ?? "", process: process, up: cu, down: cd, start: start)
            list.append(conn)
            alive.insert(id)
            let prev = seen[id] ?? (0, 0)
            usage.add(program: process.isEmpty ? L("Без программы (прокси)") : process, vpn: conn.viaVpn,
                      down: max(0, cd - prev.1), up: max(0, cu - prev.0))
            seen[id] = (cu, cd)
        }
        seen = seen.filter { alive.contains($0.key) }
        connections = list.sorted { ($0.down + $0.up) > ($1.down + $1.up) }
        usage.saveIfDue()
    }

    func close(_ id: String) async {
        _ = try? await URLSession.shared.data(for: Self.request("/connections/\(id)", method: "DELETE"))
    }

    func closeAll() async {
        _ = try? await URLSession.shared.data(for: Self.request("/connections", method: "DELETE"))
    }
}

/// Traffic per program per month: one small JSON file a month, only on this Mac.
final class MonthlyUsage {
    struct Entry: Codable { var vpnDown: Int64 = 0; var vpnUp: Int64 = 0; var directDown: Int64 = 0; var directUp: Int64 = 0
        var total: Int64 { vpnDown + vpnUp + directDown + directUp } }

    static var dir: URL {
        let u = AppGroup.container.appendingPathComponent("traffic", isDirectory: true)
        try? FileManager.default.createDirectory(at: u, withIntermediateDirectories: true)
        return u
    }

    static func key(_ d: Date) -> String {
        let f = DateFormatter()
        f.dateFormat = "yyyy-MM"
        f.locale = Locale(identifier: "en_US_POSIX")
        return f.string(from: d)
    }

    private var month = MonthlyUsage.key(Date())
    private(set) var current: [String: Entry] = MonthlyUsage.load(MonthlyUsage.key(Date()))
    private var lastSave = Date()

    static func load(_ month: String) -> [String: Entry] {
        guard let d = try? Data(contentsOf: dir.appendingPathComponent(month + ".json")) else { return [:] }
        return (try? JSONDecoder().decode([String: Entry].self, from: d)) ?? [:]
    }

    static func months() -> [String] {
        let files = (try? FileManager.default.contentsOfDirectory(atPath: dir.path)) ?? []
        var list = files.filter { $0.hasSuffix(".json") }.map { String($0.dropLast(5)) }
        if !list.contains(key(Date())) { list.append(key(Date())) }
        return list.sorted(by: >)
    }

    func add(program: String, vpn: Bool, down: Int64, up: Int64) {
        guard down > 0 || up > 0 else { return }
        let k = Self.key(Date())
        if k != month { save(); month = k; current = [:] }
        var e = current[program] ?? Entry()
        if vpn { e.vpnDown += down; e.vpnUp += up } else { e.directDown += down; e.directUp += up }
        current[program] = e
    }

    func saveIfDue() { if Date().timeIntervalSince(lastSave) > 60 { save() } }

    func save() {
        lastSave = Date()
        guard !current.isEmpty, let d = try? JSONEncoder().encode(current) else { return }
        try? d.write(to: Self.dir.appendingPathComponent(month + ".json"), options: .atomic)
    }
}

func human(_ bytes: Int64) -> String {
    let units = [L("Б"), L("КБ"), L("МБ"), L("ГБ"), L("ТБ")]
    var v = Double(max(0, bytes))
    var i = 0
    while v >= 1024, i < units.count - 1 { v /= 1024; i += 1 }
    return i == 0 ? "\(bytes) \(units[0])" : String(format: v >= 100 ? "%.0f %@" : "%.1f %@", v, units[i])
}
