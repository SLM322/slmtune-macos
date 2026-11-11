import Foundation

/// One server: a share link split into fields — the same shape as ServerProfile (Windows) and Server (Android).
struct Server: Codable, Identifiable, Hashable {
    var id: String = UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased()
    var name: String = ""
    /// vless, vmess, trojan, ss, hysteria2, hysteria, tuic, anytls, naive, socks, wireguard, group
    var kind: String = ""
    var server: String = ""
    var port: Int = 0
    var userId: String = ""
    var password: String = ""
    var params: [String: String] = [:]
    var subscriptionId: String = ""
    /// Cascade: reach this server through another one (its id).
    var viaId: String = ""
    /// Group: member ids, in order.
    var members: [String] = []
    var link: String = ""
    /// Last TCP ping, ms; -1 = not measured, -2 = no answer.
    var pingMs: Int = -1

    func param(_ key: String, _ def: String = "") -> String {
        if let v = params[key] { return v }
        return params.first { $0.key.caseInsensitiveCompare(key) == .orderedSame }?.value ?? def
    }

    var title: String { name.isEmpty ? "\(kind) \(server)" : name }

    init(id: String = UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased(),
         name: String = "", kind: String = "", server: String = "", port: Int = 0,
         userId: String = "", password: String = "", params: [String: String] = [:],
         subscriptionId: String = "", viaId: String = "", members: [String] = [], link: String = "") {
        self.id = id; self.name = name; self.kind = kind; self.server = server; self.port = port
        self.userId = userId; self.password = password; self.params = params
        self.subscriptionId = subscriptionId; self.viaId = viaId; self.members = members; self.link = link
    }

    // Tolerant decoding: settings written by an older build may miss fields.
    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        id = try c.decodeIfPresent(String.self, forKey: .id) ?? UUID().uuidString
        name = try c.decodeIfPresent(String.self, forKey: .name) ?? ""
        kind = try c.decodeIfPresent(String.self, forKey: .kind) ?? ""
        server = try c.decodeIfPresent(String.self, forKey: .server) ?? ""
        port = try c.decodeIfPresent(Int.self, forKey: .port) ?? 0
        userId = try c.decodeIfPresent(String.self, forKey: .userId) ?? ""
        password = try c.decodeIfPresent(String.self, forKey: .password) ?? ""
        params = try c.decodeIfPresent([String: String].self, forKey: .params) ?? [:]
        subscriptionId = try c.decodeIfPresent(String.self, forKey: .subscriptionId) ?? ""
        viaId = try c.decodeIfPresent(String.self, forKey: .viaId) ?? ""
        members = try c.decodeIfPresent([String].self, forKey: .members) ?? []
        link = try c.decodeIfPresent(String.self, forKey: .link) ?? ""
        pingMs = try c.decodeIfPresent(Int.self, forKey: .pingMs) ?? -1
    }
}

/// Provider subscription: the server list plus traffic and end date (subscription-userinfo).
struct Subscription: Codable, Identifiable, Hashable {
    var id: String = UUID().uuidString
    var name: String = ""
    var url: String = ""
    var autoUpdate: Bool = true
    var lastUpdate: Date? = nil
    var count: Int = 0
    var lastError: String? = nil
    var upload: Int64 = 0
    var download: Int64 = 0
    var total: Int64 = 0
    /// Unix seconds; 0 = not sent.
    var expire: Int64 = 0
}

/// The user's own rule: these sites / IPs go through the VPN, direct, or are blocked.
struct CustomRule: Codable, Identifiable, Hashable {
    var id: String = UUID().uuidString
    var name: String = ""
    /// "vpn" | "direct" | "block"
    var action: String = "vpn"
    var domains: [String] = []
    var ips: [String] = []
    var enabled: Bool = true
}

/// Protocol tuning (Windows: Settings → Протоколы), only the parts sing-box on iOS can use.
struct ProtocolSettings: Codable, Hashable {
    var tlsFragment = false
    var tlsRecordFragment = false
    /// "" = from the link; chrome, firefox, safari, edge, ios, android, random, randomized.
    var fingerprintOverride = ""
    /// "" = off; smux | yamux | h2mux.
    var multiplex = ""
    var multiplexMaxConnections = 4
    var multiplexPadding = false
    var hysteriaUpMbps = 0
    var hysteriaDownMbps = 0
    var tuicCongestion = ""
    var tuicZeroRtt = false
    var shadowsocksUdpOverTcp = false
    /// macOS: run Hysteria 2 / NaiveProxy on their official cores instead of sing-box.
    var hysteriaOfficial = false
    var naiveOfficial = false
}

/// "Мой сервер": a VPS the app sets up over SSH (same fields as Windows/Android). The password is never stored.
struct MyServer: Codable, Identifiable, Hashable {
    var id: String = UUID().uuidString
    var name: String = ""
    var host: String = ""
    var port: Int = 22
    var user: String = "root"
    /// The pinned host key ("ssh-ed25519 AAAA…"); empty until the user confirmed its fingerprint.
    var hostKey: String = ""
    /// The app's key is in the server's authorized_keys: no password needed any more.
    var keyInstalled: Bool = false
    var title: String { name.isEmpty ? host : name }
}

enum Preset: String, Codable, CaseIterable, Identifiable {
    /// Everything through the VPN.
    case all
    /// Russian sites and IPs direct, the rest through the VPN.
    case exceptRu = "except_ru"
    /// Only blocked sites through the VPN.
    case blocked
    var id: String { rawValue }
}

/// One of the user's own entries in "ИИ и игры" (sites, IPs and programs that join a group).
struct OwnService: Codable, Identifiable, Hashable {
    var id: String = UUID().uuidString
    var name: String = ""
    /// "ai" | "game" | "call"
    var group: String = "ai"
    var enabled = true
    var domains: [String] = []
    var ips: [String] = []
    /// Process names as macOS shows them in Activity Monitor ("Claude", "steam_osx").
    var processes: [String] = []
}

/// A rule for one program (TUN mode): through the VPN, direct, or blocked.
struct AppRule: Codable, Identifiable, Hashable {
    var id: String = UUID().uuidString
    var process: String = ""
    /// "vpn" | "direct" | "block"
    var action: String = "direct"
    var enabled = true
}

enum ConnectMode: String, Codable, CaseIterable, Identifiable {
    /// The whole Mac (sing-box TUN through the helper, needs it installed once).
    case tun
    /// The system proxy (browsers, Telegram and anything that honours it); no admin rights.
    case proxy
    /// Only the local proxy 127.0.0.1:port, nothing changed in the system.
    case local
    var id: String { rawValue }
}

struct AppSettings: Codable {
    var servers: [Server] = []
    var activeId: String = ""
    var subscriptions: [Subscription] = []
    var preset: Preset = .exceptRu
    var aiViaVpn = true
    var callsViaVpn = false
    var disabledServices: [String] = []
    var customRules: [CustomRule] = []
    /// Ids from Lists.blocks: ads, trackers, winspy, adult.
    var blockLists: [String] = []
    var lanBypass = true
    var ipv6 = false
    /// Cascade entry for every server ("" = off).
    var cascadeEntryId = ""
    var remoteDns = "https://1.1.1.1/dns-query"
    var directDns = "https://77.88.8.8/dns-query"
    var protocols = ProtocolSettings()

    // ---- rules by network ("Дома без VPN") ----
    var onDemandOn = false
    /// Wi-Fi names where the VPN is switched off.
    var wifiHome: [String] = []
    /// Other networks: connect automatically.
    var wifiOtherConnect = true
    var cellularConnect = true

    // ---- kill switch (pf firewall through the helper) ----
    var killSwitch = false
    var excludeLocalNetworks = true
    /// "all" | "selected"
    var killSwitchScope = "all"
    /// Selected scope: sites and IPs that never go out without the VPN.
    var killSwitchSites: [String] = []
    /// Keep the block after a manual "Отключить" and after quitting.
    var killSwitchStrict = false

    // ---- macOS ----
    var mode: ConnectMode = .proxy
    var mixedPort = 10808
    /// Games: their programs direct (lower ping), or their UDP through the VPN.
    var gameMode = true
    var gamesViaVpn = false
    var ownServices: [OwnService] = []
    var appRules: [AppRule] = []
    var autoConnect = false
    var launchAtLogin = false
    /// Self-update: "owner/repo" with releases carrying SLMtune.dmg ("" = the default repository).
    var updateRepo = ""
    var updateBeta = true
    var updateAuto = true
    var updateSkipped = ""
    /// Zapret (tpws): DPI bypass without the VPN for the listed sites.
    var zapretOn = false
    var zapretSites: [String] = ["youtube.com", "googlevideo.com", "ytimg.com", "youtu.be", "ggpht.com",
                                 "discord.com", "discord.gg", "discordapp.com", "discordapp.net", "discord.media"]
    var zapretStrategy = "split"

    var mtu = 9000
    var logLevel = "warn"
    var myServers: [MyServer] = []

    init() {}

    init(from decoder: Decoder) throws {
        let d = AppSettings()
        let c = try decoder.container(keyedBy: CodingKeys.self)
        func v<T: Decodable>(_ k: CodingKeys, _ def: T) -> T { (try? c.decodeIfPresent(T.self, forKey: k)) ?? def }
        servers = v(.servers, d.servers); activeId = v(.activeId, d.activeId)
        subscriptions = v(.subscriptions, d.subscriptions); preset = v(.preset, d.preset)
        aiViaVpn = v(.aiViaVpn, d.aiViaVpn); callsViaVpn = v(.callsViaVpn, d.callsViaVpn)
        disabledServices = v(.disabledServices, d.disabledServices); customRules = v(.customRules, d.customRules)
        blockLists = v(.blockLists, d.blockLists); lanBypass = v(.lanBypass, d.lanBypass); ipv6 = v(.ipv6, d.ipv6)
        cascadeEntryId = v(.cascadeEntryId, d.cascadeEntryId)
        remoteDns = v(.remoteDns, d.remoteDns); directDns = v(.directDns, d.directDns)
        protocols = v(.protocols, d.protocols)
        onDemandOn = v(.onDemandOn, d.onDemandOn); wifiHome = v(.wifiHome, d.wifiHome)
        wifiOtherConnect = v(.wifiOtherConnect, d.wifiOtherConnect); cellularConnect = v(.cellularConnect, d.cellularConnect)
        killSwitch = v(.killSwitch, d.killSwitch); excludeLocalNetworks = v(.excludeLocalNetworks, d.excludeLocalNetworks)
        killSwitchScope = v(.killSwitchScope, d.killSwitchScope); killSwitchSites = v(.killSwitchSites, d.killSwitchSites)
        killSwitchStrict = v(.killSwitchStrict, d.killSwitchStrict)
        mode = v(.mode, d.mode); mixedPort = v(.mixedPort, d.mixedPort)
        gameMode = v(.gameMode, d.gameMode); gamesViaVpn = v(.gamesViaVpn, d.gamesViaVpn)
        ownServices = v(.ownServices, d.ownServices); appRules = v(.appRules, d.appRules)
        autoConnect = v(.autoConnect, d.autoConnect); launchAtLogin = v(.launchAtLogin, d.launchAtLogin)
        updateRepo = v(.updateRepo, d.updateRepo); updateBeta = v(.updateBeta, d.updateBeta)
        updateAuto = v(.updateAuto, d.updateAuto); updateSkipped = v(.updateSkipped, d.updateSkipped)
        zapretOn = v(.zapretOn, d.zapretOn); zapretSites = v(.zapretSites, d.zapretSites); zapretStrategy = v(.zapretStrategy, d.zapretStrategy)
        mtu = v(.mtu, d.mtu); logLevel = v(.logLevel, d.logLevel)
        myServers = v(.myServers, d.myServers)
    }

    var activeServer: Server? { servers.first { $0.id == activeId } ?? servers.first }
    func server(_ id: String) -> Server? { servers.first { $0.id == id } }
}
