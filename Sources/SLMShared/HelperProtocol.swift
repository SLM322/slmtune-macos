import Foundation

/// The root helper (LaunchDaemon com.slmtune.helper) and the app talk over a Unix socket, one JSON object per line.
/// The helper accepts only these commands and builds every privileged action itself from their fields:
/// it never runs a command, a path or pf text sent by the app.
enum HelperProtocol {
    static let label = "com.slmtune.helper"
    static let socketPath = "/var/run/com.slmtune.helper.sock"
    static let helperPath = "/Library/PrivilegedHelperTools/com.slmtune.helper"
    static let plistPath = "/Library/LaunchDaemons/com.slmtune.helper.plist"
    /// Root-owned folder: the sing-box the helper runs, its config and log.
    static let supportDir = "/Library/Application Support/SLMtune"
    static var singBoxPath: String { supportDir + "/bin/sing-box" }
    static var runDir: String { supportDir + "/run" }
    /// The user allowed to talk to the helper (written at install: the uid of whoever installed it).
    static var ownerFile: String { supportDir + "/owner" }
    /// sing-box's log in TUN mode: readable by the app, it holds no secrets.
    static var tunLogPath: String { supportDir + "/run/singbox.log" }
    static let pfAnchor = "com.apple/400.SLMtune"
    /// Bumped when the protocol changes: the app reinstalls an older helper.
    static let version = 1

    struct Request: Codable {
        var cmd: String
        /// start: the sing-box config (JSON text).
        var config: String?
        /// proxy: on/off and the local port.
        var on: Bool?
        var port: Int?
        /// killswitch: "off" | "all" | "selected".
        var scope: String?
        var servers: [String]?
        var allowLan: Bool?
        var blocked: [String]?
        init(cmd: String) { self.cmd = cmd }
    }

    struct Reply: Codable {
        var ok: Bool
        var message: String = ""
        var running: Bool = false
        var version: Int = HelperProtocol.version
        var killSwitch: String = "off"
    }

    /// Checks a config the app sent before the helper runs it as root: no file of its own outside the allowed
    /// folders, the log and the cache in the helper's folder, no external UI. Returns the config to run.
    static func sanitize(config: String, userHome: String) throws -> String {
        guard var root = try JSONSerialization.jsonObject(with: Data(config.utf8)) as? [String: Any] else {
            throw HelperError("config is not a JSON object")
        }
        var log = root["log"] as? [String: Any] ?? [:]
        log["output"] = tunLogPath
        root["log"] = log
        var exp = root["experimental"] as? [String: Any] ?? [:]
        if var cache = exp["cache_file"] as? [String: Any] {
            cache["path"] = runDir + "/cache.db"
            exp["cache_file"] = cache
        }
        if var api = exp["clash_api"] as? [String: Any] {
            api.removeValue(forKey: "external_ui")
            api.removeValue(forKey: "external_ui_download_url")
            if let c = api["external_controller"] as? String, !c.hasPrefix("127.0.0.1:") { throw HelperError("clash_api must listen on loopback") }
            exp["clash_api"] = api
        }
        root["experimental"] = exp
        // Rule sets: only files from the user's own rules folder, nothing downloaded by root.
        let rulesDir = userHome + "/Library/Application Support/SLMtune/rules/"
        if var route = root["route"] as? [String: Any], let sets = route["rule_set"] as? [[String: Any]] {
            for s in sets {
                guard (s["type"] as? String) == "local", let p = s["path"] as? String,
                      p.hasPrefix(rulesDir), !p.contains("/../") else { throw HelperError("rule set outside the rules folder") }
            }
            route["rule_set"] = sets
            root["route"] = route
        }
        // Inbounds: TUN and loopback listeners only.
        for i in root["inbounds"] as? [[String: Any]] ?? [] {
            let t = i["type"] as? String ?? ""
            if t == "tun" { continue }
            if let l = i["listen"] as? String, l != "127.0.0.1", l != "::1" { throw HelperError("inbound must listen on loopback") }
        }
        let data = try JSONSerialization.data(withJSONObject: root, options: [.prettyPrinted, .withoutEscapingSlashes])
        return String(decoding: data, as: UTF8.self)
    }
}

struct HelperError: LocalizedError {
    let message: String
    init(_ m: String) { message = m }
    var errorDescription: String? { message }
}
