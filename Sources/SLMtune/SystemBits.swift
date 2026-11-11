import AppKit
import CoreLocation
import CoreWLAN
import CryptoKit
import Foundation
import Network
import Vision
@testable import SLMShared

// MARK: start with macOS

/// "Запускать вместе с macOS": a LaunchAgent in ~/Library/LaunchAgents (works for an unsigned app too,
/// unlike SMAppService). Started with --autostart, so the app can connect by itself and stay in the menu bar.
enum LoginItem {
    static let label = "com.slmtune.app"
    static var plist: URL {
        FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Library/LaunchAgents/\(label).plist")
    }

    static var isOn: Bool { FileManager.default.fileExists(atPath: plist.path) }

    static func set(_ on: Bool) throws {
        if !on { try? FileManager.default.removeItem(at: plist); return }
        guard let exe = Bundle.main.executablePath else { return }
        let text = """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0"><dict>
          <key>Label</key><string>\(label)</string>
          <key>ProgramArguments</key><array><string>\(exe)</string><string>--autostart</string></array>
          <key>RunAtLoad</key><true/>
          <key>ProcessType</key><string>Interactive</string>
        </dict></plist>
        """
        try FileManager.default.createDirectory(at: plist.deletingLastPathComponent(), withIntermediateDirectories: true)
        try text.write(to: plist, atomically: true, encoding: .utf8)
    }
}

// MARK: rules by network

/// Watches the network: on a change, tells the app the current Wi-Fi name ("" for a cable or none).
/// macOS 14+ shows the Wi-Fi name only to apps with Location access, so the app asks for it once.
@MainActor
final class NetworkWatcher: NSObject, ObservableObject, CLLocationManagerDelegate {
    @Published private(set) var wifi: String = ""
    @Published private(set) var onCable = false
    var onChange: ((String) -> Void)?
    private let monitor = NWPathMonitor()
    private let location = CLLocationManager()
    private var last: String?

    override init() {
        super.init()
        location.delegate = self
        monitor.pathUpdateHandler = { [weak self] path in
            Task { @MainActor in
                // Let the new network settle (DHCP, the Wi-Fi name) before deciding.
                try? await Task.sleep(nanoseconds: 2_500_000_000)
                self?.refresh(path)
            }
        }
        monitor.start(queue: .main)
    }

    func askLocation() { location.requestWhenInUseAuthorization() }

    var locationAllowed: Bool {
        let s = location.authorizationStatus
        return s == .authorizedAlways || s == .authorized
    }

    nonisolated func locationManagerDidChangeAuthorization(_ manager: CLLocationManager) {
        Task { @MainActor in self.refresh(self.monitor.currentPath) }
    }

    private func refresh(_ path: NWPath) {
        wifi = CWWiFiClient.shared().interface()?.ssid() ?? ""
        onCable = path.usesInterfaceType(.wiredEthernet)
        let key = path.status == .satisfied ? (wifi.isEmpty ? (onCable ? "#cable" : "#other") : wifi) : "#offline"
        if key != last {
            let first = last == nil
            last = key
            if !first, key != "#offline" { onChange?(wifi) }
        }
    }
}

// MARK: QR codes

enum ScreenQR {
    /// Every QR code on every display (needs the Screen Recording permission once).
    static func readScreens() -> [String] {
        var found: [String] = []
        var count: UInt32 = 0
        CGGetActiveDisplayList(0, nil, &count)
        var ids = [CGDirectDisplayID](repeating: 0, count: Int(count))
        CGGetActiveDisplayList(count, &ids, &count)
        for id in ids {
            if let img = CGDisplayCreateImage(id) { found += decode(img) }
        }
        var seen = Set<String>()
        return found.filter { seen.insert($0).inserted }
    }

    static func decode(_ image: CGImage) -> [String] {
        let req = VNDetectBarcodesRequest()
        req.symbologies = [.qr]
        try? VNImageRequestHandler(cgImage: image).perform([req])
        return (req.results ?? []).compactMap { $0.payloadStringValue }
    }

    static func decode(file: URL) -> [String] {
        guard let img = NSImage(contentsOf: file), let cg = img.cgImage(forProposedRect: nil, context: nil, hints: nil) else { return [] }
        return decode(cg)
    }

    static var screenAccess: Bool { CGPreflightScreenCaptureAccess() }
    static func askScreenAccess() { CGRequestScreenCaptureAccess() }

    /// A QR picture of a link (for "Поделиться").
    static func image(_ text: String, size: CGFloat = 260) -> NSImage? {
        guard let f = CIFilter(name: "CIQRCodeGenerator") else { return nil }
        f.setValue(Data(text.utf8), forKey: "inputMessage")
        f.setValue("M", forKey: "inputCorrectionLevel")
        guard let out = f.outputImage else { return nil }
        let scaled = out.transformed(by: CGAffineTransform(scaleX: size / out.extent.width, y: size / out.extent.height))
        let rep = NSCIImageRep(ciImage: scaled)
        let img = NSImage(size: rep.size)
        img.addRepresentation(rep)
        return img
    }
}

// MARK: Cloudflare WARP

enum Warp {
    /// Registers a free WARP device (the same call the official app makes) and returns a WireGuard server for
    /// sing-box, or AmneziaWG for mihomo with junk packets before the handshake (gets past DPI that drops plain WireGuard).
    static func register(obfuscate: Bool) async throws -> Server {
        let priv = Curve25519.KeyAgreement.PrivateKey()
        let pub = priv.publicKey.rawRepresentation.base64EncodedString()
        var req = URLRequest(url: URL(string: "https://api.cloudflareclient.com/v0a2158/reg")!, timeoutInterval: 30)
        req.httpMethod = "POST"
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        req.setValue("okhttp/3.12.1", forHTTPHeaderField: "User-Agent")
        req.setValue("a-6.30-3596", forHTTPHeaderField: "CF-Client-Version")
        let tos = ISO8601DateFormatter().string(from: Date())
        req.httpBody = try JSONSerialization.data(withJSONObject: ["key": pub, "install_id": "", "fcm_token": "", "tos": tos,
                                                                   "model": "PC", "type": "Android", "locale": "en_US"])
        let (data, resp) = try await URLSession.shared.data(for: req)
        guard let http = resp as? HTTPURLResponse, (200..<300).contains(http.statusCode) else {
            throw LinkError(L("Cloudflare не зарегистрировал WARP (HTTP %d). Попробуйте позже или через VPN.", (resp as? HTTPURLResponse)?.statusCode ?? 0))
        }
        guard let root = try JSONSerialization.jsonObject(with: data) as? [String: Any], let cfg = root["config"] as? [String: Any],
              let peer = (cfg["peers"] as? [[String: Any]])?.first, let peerKey = peer["public_key"] as? String else {
            throw LinkError(L("Cloudflare ответил без настроек WARP."))
        }
        let addrs = (cfg["interface"] as? [String: Any])?["addresses"] as? [String: Any]
        let v4 = addrs?["v4"] as? String ?? "172.16.0.2"
        let v6 = addrs?["v6"] as? String ?? ""
        var reserved = ""
        if let cid = cfg["client_id"] as? String, let raw = Data(base64Encoded: cid) { reserved = raw.prefix(3).map(String.init).joined(separator: ",") }
        var params: [String: String] = ["publickey": peerKey, "address": v6.isEmpty ? "\(v4)/32" : "\(v4)/32,\(v6)/128",
                                        "mtu": "1280", "dns": "1.1.1.1,1.0.0.1", "warp": "1"]
        if !reserved.isEmpty { params["reserved"] = reserved }
        if obfuscate {
            for (k, v) in ["jc": "4", "jmin": "40", "jmax": "70", "s1": "0", "s2": "0", "h1": "1", "h2": "2", "h3": "3", "h4": "4"] { params[k] = v }
        }
        return Server(name: obfuscate ? "Cloudflare WARP (AmneziaWG)" : "Cloudflare WARP", kind: obfuscate ? "amneziawg" : "wireguard",
                      server: "162.159.192.1", port: 2408, password: priv.rawRepresentation.base64EncodedString(), params: params)
    }
}

// MARK: self-update

/// New versions from GitHub Releases: "SLMtune.dmg" with the SHA-256 GitHub publishes. The app replaces itself
/// (hdiutil + ditto) and starts again; settings stay in Application Support.
enum AppUpdater {
    static let defaultRepo = "SLM322/slmtune-macos"
    struct Update { let version: String; let notes: String; let url: URL; let sha256: String; let size: Int64 }

    static var currentVersion: String { Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "0" }

    static func check(_ s: AppSettings) async throws -> Update? {
        let repo = s.updateRepo.isEmpty ? defaultRepo : s.updateRepo
        for rel in try await GitHub.releases(repo) {
            if rel["draft"] as? Bool == true { continue }
            if rel["prerelease"] as? Bool == true, !s.updateBeta { continue }
            let tag = ((rel["tag_name"] as? String) ?? "").trimmingCharacters(in: CharacterSet(charactersIn: "vV"))
            guard Cores.isNewer(tag, than: currentVersion) else { return nil }
            guard let a = (rel["assets"] as? [[String: Any]])?.first(where: { ($0["name"] as? String)?.hasSuffix(".dmg") == true }),
                  let u = (a["browser_download_url"] as? String).flatMap(URL.init(string:)),
                  let digest = a["digest"] as? String, digest.hasPrefix("sha256:") else { continue }
            return Update(version: tag, notes: rel["body"] as? String ?? "", url: u, sha256: String(digest.dropFirst(7)).lowercased(),
                          size: (a["size"] as? NSNumber)?.int64Value ?? 0)
        }
        return nil
    }

    /// Downloads, checks, and swaps the app in place; then relaunches. Throws before touching anything on a bad file.
    static func install(_ u: Update) async throws {
        let (tmp, _) = try await URLSession.shared.download(from: u.url)
        let dmg = AppGroup.tempDir.appendingPathComponent("SLMtune-\(u.version).dmg")
        try? FileManager.default.removeItem(at: dmg)
        try FileManager.default.moveItem(at: tmp, to: dmg)
        guard Cores.sha256(dmg) == u.sha256 else {
            try? FileManager.default.removeItem(at: dmg)
            throw LinkError(L("Контрольная сумма обновления не совпала с GitHub — обновление отменено."))
        }
        let app = Bundle.main.bundleURL.path
        let pid = ProcessInfo.processInfo.processIdentifier
        // A small script waits for us to quit, mounts the image, replaces the app and opens it again.
        let script = """
        while kill -0 \(pid) 2>/dev/null; do sleep 0.3; done
        M=$(mktemp -d)
        hdiutil attach -nobrowse -readonly -mountpoint "$M" '\(dmg.path)' >/dev/null || exit 1
        rm -rf '\(app).old'; mv '\(app)' '\(app).old' && ditto "$M/SLMtune.app" '\(app)' && rm -rf '\(app).old' || mv '\(app).old' '\(app)'
        hdiutil detach "$M" >/dev/null
        xattr -dr com.apple.quarantine '\(app)' 2>/dev/null
        open '\(app)'
        rm -f '\(dmg.path)'
        """
        let f = AppGroup.tempDir.appendingPathComponent("update.sh")
        try script.write(to: f, atomically: true, encoding: .utf8)
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/bin/sh")
        p.arguments = [f.path]
        try p.run()
    }
}
