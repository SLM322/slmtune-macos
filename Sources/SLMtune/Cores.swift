import CryptoKit
import Foundation
@testable import SLMShared

/// The cores. The app ships them in Contents/Resources/cores (universal binaries, checked against GitHub's SHA-256 at
/// build time); a core updated later lives in ~/Library/Application Support/SLMtune/cores and wins.
enum CoreName: String, CaseIterable, Identifiable {
    case singBox = "sing-box", xray, mihomo, hysteria, naive, trusttunnel = "trusttunnel_client", tor, tpws
    var id: String { rawValue }

    var title: String {
        switch self {
        case .singBox: return "sing-box"
        case .xray: return "Xray"
        case .mihomo: return "mihomo"
        case .hysteria: return "Hysteria 2"
        case .naive: return "NaiveProxy"
        case .trusttunnel: return "TrustTunnel"
        case .tor: return "Tor"
        case .tpws: return "Zapret (tpws)"
        }
    }

    var purpose: String {
        switch self {
        case .singBox: return L("TUN, правила, DNS; VLESS, Trojan, Shadowsocks, Hysteria2, TUIC, AnyTLS, NaiveProxy, WireGuard")
        case .xray: return L("VLESS XHTTP и VLESS Encryption")
        case .mihomo: return L("AmneziaWG, mieru, ShadowsocksR, ShadowTLS")
        case .hysteria: return L("официальный клиент Hysteria 2: прыжки по портам")
        case .naive: return L("официальный NaiveProxy на сетевом стеке Chrome")
        case .trusttunnel: return L("TrustTunnel (AdGuard)")
        case .tor: return L("Tor с мостами obfs4, webtunnel, snowflake, meek")
        case .tpws: return L("обход DPI без VPN для выбранных сайтов")
        }
    }

    /// GitHub repository and asset pattern for in-app updates (nil: updated together with the app).
    var release: (repo: String, pattern: String)? {
        let arm = Cores.isArm
        switch self {
        case .singBox: return ("SagerNet/sing-box", arm ? #"^sing-box-[\d.]+-darwin-arm64\.tar\.gz$"# : #"^sing-box-[\d.]+-darwin-amd64\.tar\.gz$"#)
        case .xray: return ("XTLS/Xray-core", arm ? #"^Xray-macos-arm64-v8a\.zip$"# : #"^Xray-macos-64\.zip$"#)
        case .mihomo: return ("MetaCubeX/mihomo", arm ? #"^mihomo-darwin-arm64-v[\d.]+\.gz$"# : #"^mihomo-darwin-amd64-compatible-v[\d.]+\.gz$"#)
        case .hysteria: return ("apernet/hysteria", arm ? #"^hysteria-darwin-arm64$"# : #"^hysteria-darwin-amd64$"#)
        case .naive: return ("klzgrad/naiveproxy", arm ? #"^naiveproxy-v[\d.]+-\d+-mac-arm64-arm64\.tar\.xz$"# : #"^naiveproxy-v[\d.]+-\d+-mac-x64-x64\.tar\.xz$"#)
        case .trusttunnel: return ("TrustTunnel/TrustTunnelClient", #"^trusttunnel_client-v[\d.]+-macos-universal\.tar\.gz$"#)
        case .tor, .tpws: return nil
        }
    }

    /// Arguments that make the core print its version.
    var versionArgs: [String] {
        switch self {
        case .singBox, .xray, .hysteria: return ["version"]
        case .mihomo: return ["-v"]
        case .naive: return ["--version"]
        case .trusttunnel: return ["--version"]
        case .tor: return ["--version"]
        case .tpws: return ["--version"]
        }
    }
}

enum Cores {
    static var isArm: Bool {
        var info = utsname()
        uname(&info)
        let machine = withUnsafeBytes(of: &info.machine) { String(decoding: $0.prefix { $0 != 0 }, as: UTF8.self) }
        return machine.hasPrefix("arm")
    }

    static var bundled: URL { Bundle.main.resourceURL!.appendingPathComponent("cores", isDirectory: true) }

    /// Relative path of a core inside a cores folder.
    static func relative(_ c: CoreName) -> String { c == .tor ? "tor/tor" : c.rawValue }

    static func path(_ c: CoreName) -> URL? {
        for base in [AppGroup.coresDir, bundled] {
            let u = base.appendingPathComponent(relative(c))
            if FileManager.default.isExecutableFile(atPath: u.path) { return u }
        }
        return nil
    }

    static var torPluggableTransports: URL { bundled.appendingPathComponent("tor/pluggable_transports") }
    static var torGeoIP: URL { bundled.appendingPathComponent("tor/data") }

    /// "1.14.4" from the core's own output (first version-looking number).
    static func version(_ c: CoreName) -> String? {
        guard let p = path(c) else { return nil }
        let pr = Process()
        pr.executableURL = p
        pr.arguments = c.versionArgs
        let pipe = Pipe()
        pr.standardOutput = pipe
        pr.standardError = pipe
        guard (try? pr.run()) != nil else { return nil }
        let deadline = Date().addingTimeInterval(5)
        while pr.isRunning && Date() < deadline { usleep(50_000) }
        if pr.isRunning { pr.terminate() }
        let text = String(decoding: pipe.fileHandleForReading.availableData, as: UTF8.self)
        guard let r = text.range(of: #"v?\d+\.\d+(\.\d+)?(\.\d+)?(-\d+)?"#, options: .regularExpression) else { return "?" }
        return String(text[r]).trimmingCharacters(in: CharacterSet(charactersIn: "v"))
    }

    static func sha256(_ url: URL) -> String? {
        guard let d = try? Data(contentsOf: url) else { return nil }
        return SHA256.hash(data: d).map { String(format: "%02x", $0) }.joined()
    }

    // MARK: updates from GitHub

    struct Release { let core: CoreName; let version: String; let url: URL; let sha256: String; let name: String }

    static func latest(_ c: CoreName) async throws -> Release {
        guard let (repo, pattern) = c.release else { throw LinkError(L("Это ядро обновляется вместе с программой.")) }
        let json = try await GitHub.latestRelease(repo)
        let tag = (json["tag_name"] as? String) ?? ""
        let assets = json["assets"] as? [[String: Any]] ?? []
        guard let a = assets.first(where: { ($0["name"] as? String)?.range(of: pattern, options: .regularExpression) != nil }),
              let name = a["name"] as? String, let u = (a["browser_download_url"] as? String).flatMap(URL.init(string:)) else {
            throw LinkError(L("%@: в релизе %@ нет сборки для этого Mac.", c.title, tag))
        }
        let digest = a["digest"] as? String ?? ""
        guard digest.hasPrefix("sha256:") else { throw LinkError(L("%@: GitHub не отдал контрольную сумму — обновление небезопасно.", c.title)) }
        return Release(core: c, version: tag.components(separatedBy: "/").last!.trimmingCharacters(in: CharacterSet(charactersIn: "vV")),
                       url: u, sha256: String(digest.dropFirst(7)).lowercased(), name: name)
    }

    /// Downloads, checks SHA-256, unpacks and puts the core into the user's cores folder.
    static func install(_ r: Release) async throws {
        let work = AppGroup.tempDir.appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: work, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: work) }
        let (tmp, _) = try await URLSession.shared.download(from: r.url)
        let archive = work.appendingPathComponent(r.name)
        try FileManager.default.moveItem(at: tmp, to: archive)
        guard sha256(archive) == r.sha256 else { throw LinkError(L("%@: контрольная сумма не совпала с GitHub. Обновление отменено.", r.core.title)) }
        let x = work.appendingPathComponent("x", isDirectory: true)
        try FileManager.default.createDirectory(at: x, withIntermediateDirectories: true)
        let n = r.name
        if n.hasSuffix(".zip") { try Shell.run("/usr/bin/unzip", ["-q", archive.path, "-d", x.path]) }
        else if n.hasSuffix(".tar.gz") || n.hasSuffix(".tar.xz") { try Shell.run("/usr/bin/tar", ["-xf", archive.path, "-C", x.path]) }
        else if n.hasSuffix(".gz") { try Shell.run("/bin/sh", ["-c", "/usr/bin/gunzip -c \"$0\" > \"$1\"", archive.path, x.appendingPathComponent(r.core.rawValue).path]) }
        else { try FileManager.default.copyItem(at: archive, to: x.appendingPathComponent(r.core.rawValue)) }
        // The executable: the file named like the core (Xray: "xray", naive: "naive", tt: "trusttunnel_client").
        let wanted = [r.core.rawValue, r.core == .xray ? "xray" : "", r.core == .naive ? "naive" : ""].filter { !$0.isEmpty }
        let found = FileManager.default.enumerator(at: x, includingPropertiesForKeys: nil)?.compactMap { $0 as? URL }
            .first { wanted.contains($0.lastPathComponent) }
        guard let bin = found else { throw LinkError(L("%@: в архиве нет исполняемого файла.", r.core.title)) }
        let dest = AppGroup.coresDir.appendingPathComponent(r.core.rawValue)
        try? FileManager.default.removeItem(at: dest)
        try FileManager.default.copyItem(at: bin, to: dest)
        try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: dest.path)
        // Downloaded files carry the quarantine flag: Gatekeeper would stop the unsigned binary.
        _ = try? Shell.run("/usr/bin/xattr", ["-d", "com.apple.quarantine", dest.path])
        // naive needs no libraries; sing-box from GitHub may come with libcronet: copy it too.
        if let lib = FileManager.default.enumerator(at: x, includingPropertiesForKeys: nil)?.compactMap({ $0 as? URL }).first(where: { $0.pathExtension == "dylib" }) {
            let d = AppGroup.coresDir.appendingPathComponent(lib.lastPathComponent)
            try? FileManager.default.removeItem(at: d)
            try? FileManager.default.copyItem(at: lib, to: d)
        }
    }

    static func isNewer(_ latest: String, than current: String?) -> Bool {
        guard let current else { return true }
        let a = latest.split(whereSeparator: { !$0.isNumber }).compactMap { Int($0) }
        let b = current.split(whereSeparator: { !$0.isNumber }).compactMap { Int($0) }
        for i in 0..<max(a.count, b.count) {
            let x = i < a.count ? a[i] : 0, y = i < b.count ? b[i] : 0
            if x != y { return x > y }
        }
        return false
    }
}

enum GitHub {
    static func latestRelease(_ repo: String) async throws -> [String: Any] {
        try await get("https://api.github.com/repos/\(repo)/releases/latest") as? [String: Any] ?? [:]
    }

    static func releases(_ repo: String) async throws -> [[String: Any]] {
        try await get("https://api.github.com/repos/\(repo)/releases?per_page=10") as? [[String: Any]] ?? []
    }

    private static func get(_ url: String) async throws -> Any {
        var req = URLRequest(url: URL(string: url)!, timeoutInterval: 30)
        req.setValue("SLMtune-macOS", forHTTPHeaderField: "User-Agent")
        req.setValue("application/vnd.github+json", forHTTPHeaderField: "Accept")
        let (data, resp) = try await URLSession.shared.data(for: req)
        if let h = resp as? HTTPURLResponse, h.statusCode != 200 { throw LinkError(L("GitHub ответил %d.", h.statusCode)) }
        return try JSONSerialization.jsonObject(with: data)
    }
}

/// Running a system tool and getting its output.
enum Shell {
    @discardableResult
    static func run(_ path: String, _ args: [String], input: String? = nil) throws -> String {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: path)
        p.arguments = args
        let out = Pipe()
        p.standardOutput = out
        p.standardError = out
        let inPipe = Pipe()
        if input != nil { p.standardInput = inPipe }
        try p.run()
        if let input {
            inPipe.fileHandleForWriting.write(Data(input.utf8))
            try? inPipe.fileHandleForWriting.close()
        }
        let data = out.fileHandleForReading.readDataToEndOfFile()
        p.waitUntilExit()
        let text = String(decoding: data, as: UTF8.self)
        if p.terminationStatus != 0 {
            throw LinkError("\((path as NSString).lastPathComponent): " + text.trimmingCharacters(in: .whitespacesAndNewlines))
        }
        return text
    }
}
