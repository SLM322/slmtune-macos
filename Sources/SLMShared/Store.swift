import Foundation

/// Where SLMtune keeps its files on the Mac: ~/Library/Application Support/SLMtune (the layout the iOS App Group
/// had). The helper (root) gets what it needs in each request and never reads this folder itself.
enum AppGroup {
    /// SLM_DATA_DIR: the checks run with their own folder.
    static var container: URL {
        if let d = ProcessInfo.processInfo.environment["SLM_DATA_DIR"], !d.isEmpty {
            let u = URL(fileURLWithPath: d, isDirectory: true)
            try? FileManager.default.createDirectory(at: u, withIntermediateDirectories: true)
            return u
        }
        let u = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("SLMtune", isDirectory: true)
        try? FileManager.default.createDirectory(at: u, withIntermediateDirectories: true)
        return u
    }

    static var isShared: Bool { true }

    static var settingsFile: URL { container.appendingPathComponent("settings.json") }
    static var rulesDir: URL { dir("rules") }
    static var workingDir: URL { dir("work") }
    static var tempDir: URL { dir("tmp") }
    /// Configs of the running cores; they hold passwords, so they are removed on disconnect.
    static var runtimeDir: URL { dir("runtime") }
    /// Cores downloaded or updated after install (they win over the ones inside the app).
    static var coresDir: URL { dir("cores") }
    static var lastErrorFile: URL { container.appendingPathComponent("last-error.txt") }
    static var lastConfigFile: URL { container.appendingPathComponent("last-config.json") }

    /// sing-box's Clash API (connections, traffic): loopback only, with a per-install secret.
    static let clashPort = 19090
    static var secretOverride: String?
    static var clashSecret: String {
        if let o = secretOverride, o.count >= 16 { return o }
        let url = container.appendingPathComponent("api-secret")
        if let s = try? String(contentsOf: url, encoding: .utf8), s.count >= 16 { return s }
        let bytes = (0..<18).map { _ in UInt8.random(in: 0...255) }
        let s = Data(bytes).base64EncodedString().replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "+", with: "-")
        try? s.write(to: url, atomically: true, encoding: .utf8)
        try? FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
        return s
    }

    private static func dir(_ name: String) -> URL {
        let u = container.appendingPathComponent(name, isDirectory: true)
        try? FileManager.default.createDirectory(at: u, withIntermediateDirectories: true)
        return u
    }
}

/// Settings in one JSON file, readable only by the user (it holds server passwords).
enum SettingsFile {
    static func load() -> AppSettings {
        guard let data = try? Data(contentsOf: AppGroup.settingsFile),
              let s = try? JSONDecoder().decode(AppSettings.self, from: data) else { return AppSettings() }
        return s
    }

    static func encoded(_ s: AppSettings) -> Data { (try? JSONEncoder().encode(s)) ?? Data() }

    static func decode(_ data: Data?) -> AppSettings? {
        guard let data else { return nil }
        return try? JSONDecoder().decode(AppSettings.self, from: data)
    }

    static func save(_ s: AppSettings) {
        guard let data = try? JSONEncoder().encode(s) else { return }
        try? data.write(to: AppGroup.settingsFile, options: .atomic)
        try? FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: AppGroup.settingsFile.path)
    }

    /// Writes a runtime config readable only by the user.
    static func writePrivate(_ text: String, to url: URL) throws {
        try Data(text.utf8).write(to: url, options: .atomic)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
    }
}
