import Foundation

/// macOS program names (as sing-box sees them in TUN: the executable's name) for the AI, game and call services,
/// plus the user's own entries. Domains of the built-in services live in Catalog (shared with iOS and Android).
enum MacRules {
    /// Service id (Catalog / games list) → process names on macOS.
    static let processesById: [String: [String]] = [
        // AI
        "chatgpt": ["ChatGPT", "ChatGPT Helper", "codex", "Codex"],
        "claude": ["Claude", "Claude Helper", "claude"],
        "gemini": ["gemini"],
        "antigravity": ["Antigravity", "Antigravity Helper"],
        "copilot": ["Copilot", "Microsoft Copilot"],
        "perplexity": ["Perplexity", "Comet", "Comet Helper"],
        "cursor": ["Cursor", "Cursor Helper", "cursor-agent"],
        "windsurf": ["Windsurf", "Windsurf Helper"],
        "coding": ["Kiro", "Trae", "Zed", "Warp", "stable", "opencode", "aider", "goose", "crush", "droid", "amp", "Qoder"],
        "local": ["ollama", "Ollama", "LM Studio", "Jan", "Msty", "Cherry Studio", "AnythingLLM"],
        "chats": ["Poe"],
        // calls
        "discord": ["Discord", "Discord Helper", "Discord Helper (Renderer)"],
        "telegram": ["Telegram", "AyuGram"],
        "whatsapp": ["WhatsApp"],
        "signal": ["Signal", "Signal Helper"],
    ]

    /// Games and launchers (Catalog has no games: iOS can't route by program).
    struct Game: Identifiable, Hashable {
        let id: String
        let name: String
        let processes: [String]
    }

    static let games: [Game] = [
        Game(id: "steam", name: "Steam", processes: ["steam_osx", "Steam", "steamwebhelper", "Steam Helper"]),
        Game(id: "valve", name: "CS2, Dota 2, Deadlock", processes: ["cs2", "dota2", "csgo_osx64", "project8"]),
        Game(id: "epic", name: "Epic Games · Fortnite", processes: ["EpicGamesLauncher", "Epic Games Launcher", "FortniteClient-Mac-Shipping"]),
        Game(id: "battlenet", name: "Battle.net · WoW · Diablo", processes: ["Battle.net", "World of Warcraft", "Wow", "Diablo IV", "Hearthstone"]),
        Game(id: "riot", name: "Riot · League of Legends", processes: ["RiotClientServices", "Riot Client", "LeagueClient", "League of Legends"]),
        Game(id: "minecraft", name: "Minecraft", processes: ["Minecraft", "java"]),
        Game(id: "roblox", name: "Roblox", processes: ["RobloxPlayer", "Roblox"]),
        Game(id: "ea", name: "EA app", processes: ["EA app", "EADesktop"]),
        Game(id: "gog", name: "GOG Galaxy", processes: ["GOG Galaxy"]),
        Game(id: "lesta", name: "Мир кораблей · War Thunder", processes: ["WorldOfWarships", "aces"]),
        Game(id: "genshin", name: "Genshin Impact", processes: ["GenshinImpact", "Genshin Impact"]),
    ]

    static func isOn(_ s: AppSettings, _ id: String) -> Bool { !s.disabledServices.contains(id) }

    private static func uniq(_ a: [String]) -> [String] {
        var seen = Set<String>()
        return a.filter { !$0.isEmpty && seen.insert($0).inserted }
    }

    /// Program names of a group: built-in services that are on, plus the user's own entries.
    static func processes(_ s: AppSettings, group: String) -> [String] {
        var list: [String] = []
        switch group {
        case "ai":
            for d in Catalog.inGroup(.ai) where isOn(s, d.id) { list += processesById[d.id] ?? [] }
        case "call":
            for d in Catalog.inGroup(.call) where isOn(s, d.id) { list += processesById[d.id] ?? [] }
        case "game":
            for g in games where isOn(s, g.id) { list += g.processes }
        default: break
        }
        list += s.ownServices.filter { $0.enabled && $0.group == group }.flatMap(\.processes)
        return uniq(list.map { $0.trimmingCharacters(in: .whitespaces) })
    }

    static func ownDomains(_ s: AppSettings, group: String) -> [String] {
        uniq(s.ownServices.filter { $0.enabled && $0.group == group }.flatMap(\.domains).map(clean))
    }

    static func ownIps(_ s: AppSettings, group: String) -> [String] {
        uniq(s.ownServices.filter { $0.enabled && $0.group == group }.flatMap(\.ips).map { $0.trimmingCharacters(in: .whitespaces) }.filter(isAddress))
    }

    /// "https://www.site.com/x" → "site.com"; "*.site.com" → "site.com".
    static func clean(_ d: String) -> String {
        var d = d.trimmingCharacters(in: .whitespaces).lowercased()
        if d.contains("://"), let h = URL(string: d)?.host { d = h }
        while d.hasPrefix("*") || d.hasPrefix(".") { d.removeFirst() }
        while d.hasSuffix("/") || d.hasSuffix(".") { d.removeLast() }
        if d.hasPrefix("www.") { d.removeFirst(4) }
        return d
    }

    /// "1.2.3.4", "1.2.3.0/24", "2001:db8::/32".
    static func isAddress(_ e: String) -> Bool {
        let parts = e.split(separator: "/", omittingEmptySubsequences: false)
        guard parts.count <= 2, let ip = parts.first else { return false }
        let s = String(ip)
        let v4 = s.split(separator: ".", omittingEmptySubsequences: false)
        let isV4 = v4.count == 4 && v4.allSatisfy { UInt8($0) != nil }
        let isV6 = !isV4 && s.contains(":") && s.allSatisfy { $0.isHexDigit || $0 == ":" || $0 == "." }
        guard isV4 || isV6 else { return false }
        if parts.count == 2 {
            guard let bits = Int(parts[1]) else { return false }
            return bits >= 0 && bits <= (isV4 ? 32 : 128)
        }
        return true
    }

    // MARK: kill switch (pf)

    /// The pf anchor the helper loads for the kill switch. "all": everything out is blocked except the tunnel
    /// interfaces (utun*), loopback, the local network and the VPN servers themselves; "selected": only the listed
    /// addresses are blocked outside the tunnel. Built here (pure text) so the checks can verify it.
    static func pfRules(scope: String, servers: [String], allowLan: Bool, blockedAddresses: [String]) -> String {
        var r: [String] = []
        let tun = "utun"
        if scope == "all" {
            r.append("pass out quick on lo0 all")
            for i in 0...15 { r.append("pass out quick on \(tun)\(i) all") }
            if allowLan {
                for n in ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "224.0.0.0/4", "255.255.255.255", "fe80::/10", "ff00::/8"] {
                    r.append("pass out quick to \(n)")
                }
                r.append("pass out quick proto udp from any port 68 to any port 67")
            }
            let addrs = uniq(servers.filter(isAddress))
            if !addrs.isEmpty { r.append("pass out quick to { \(addrs.joined(separator: ", ")) }") }
            // DNS through the system resolver, so the cores find the servers by name before the tunnel is up.
            r.append("pass out quick proto { udp, tcp } to any port 53 user _mdnsresponder")
            r.append("block drop out quick all")
        } else {
            let addrs = uniq(blockedAddresses.filter(isAddress))
            if !addrs.isEmpty {
                for i in 0...15 { r.append("pass out quick on \(tun)\(i) to { \(addrs.joined(separator: ", ")) }") }
                r.append("block drop out quick to { \(addrs.joined(separator: ", ")) }")
            }
        }
        return r.joined(separator: "\n") + "\n"
    }
}
