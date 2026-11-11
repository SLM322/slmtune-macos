import Darwin
import Foundation
@testable import SLMShared

/// Talks to the root helper (see SLMtuneHelper) and installs it. Installing asks for the admin password once
/// (macOS's own dialog); after that TUN, the system proxy and the kill switch work without asking again.
enum HelperClient {
    static var isInstalled: Bool {
        FileManager.default.fileExists(atPath: HelperProtocol.helperPath) && FileManager.default.fileExists(atPath: HelperProtocol.socketPath)
    }

    /// Sends one request; nil when the helper isn't there or doesn't answer.
    static func send(_ r: HelperProtocol.Request, timeout: TimeInterval = 30) async -> HelperProtocol.Reply? {
        await Task.detached { sendSync(r, timeout: timeout) }.value
    }

    private static func sendSync(_ r: HelperProtocol.Request, timeout: TimeInterval) -> HelperProtocol.Reply? {
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { return nil }
        defer { close(fd) }
        var tv = timeval(tv_sec: Int(timeout), tv_usec: 0)
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))
        var noSigPipe: Int32 = 1
        setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &noSigPipe, socklen_t(MemoryLayout<Int32>.size))
        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        withUnsafeMutableBytes(of: &addr.sun_path) { raw in
            let bytes = Array(HelperProtocol.socketPath.utf8.prefix(raw.count - 1))
            raw.copyBytes(from: bytes + [0])
        }
        let ok = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { connect(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size)) }
        }
        guard ok == 0, var data = try? JSONEncoder().encode(r) else { return nil }
        data.append(10)
        _ = data.withUnsafeBytes { write(fd, $0.baseAddress, $0.count) }
        var buf = Data()
        var chunk = [UInt8](repeating: 0, count: 65536)
        while true {
            let n = read(fd, &chunk, chunk.count)
            if n <= 0 { break }
            buf.append(contentsOf: chunk[0..<n])
            if chunk[0..<n].contains(10) { break }
        }
        guard let line = buf.split(separator: 10).first else { return nil }
        return try? JSONDecoder().decode(HelperProtocol.Reply.self, from: Data(line))
    }

    /// Whether the installed helper speaks our protocol version.
    static func isCurrent() async -> Bool {
        guard isInstalled, let r = await send(.init(cmd: "ping"), timeout: 3) else { return false }
        return r.version == HelperProtocol.version
    }

    /// Installs (or reinstalls) the helper and the sing-box it runs. Shows macOS's admin password dialog.
    static func install() async throws {
        guard let helper = Bundle.main.url(forResource: "SLMtuneHelper", withExtension: nil, subdirectory: "helper") else {
            throw LinkError(L("В программе нет помощника — пересоберите или переустановите SLMtune."))
        }
        guard let singBox = Cores.path(.singBox) else { throw LinkError(L("Не найдено ядро sing-box.")) }
        let plist = """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0"><dict>
          <key>Label</key><string>\(HelperProtocol.label)</string>
          <key>ProgramArguments</key><array><string>\(HelperProtocol.helperPath)</string></array>
          <key>RunAtLoad</key><true/>
          <key>KeepAlive</key><true/>
          <key>StandardOutPath</key><string>/var/log/com.slmtune.helper.log</string>
          <key>StandardErrorPath</key><string>/var/log/com.slmtune.helper.log</string>
        </dict></plist>
        """
        let work = AppGroup.tempDir.appendingPathComponent("helper-install-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: work, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: work) }
        let plistFile = work.appendingPathComponent("helper.plist")
        try plist.write(to: plistFile, atomically: true, encoding: .utf8)
        func q(_ s: String) -> String { "'" + s.replacingOccurrences(of: "'", with: "'\\''") + "'" }
        let dir = HelperProtocol.supportDir
        let script = """
        set -e
        launchctl bootout system/\(HelperProtocol.label) 2>/dev/null || true
        mkdir -p \(q(dir + "/bin")) \(q(dir + "/run")) /Library/PrivilegedHelperTools
        install -m 755 -o root -g wheel \(q(helper.path)) \(q(HelperProtocol.helperPath))
        install -m 755 -o root -g wheel \(q(singBox.path)) \(q(HelperProtocol.singBoxPath))
        for lib in \(q(singBox.deletingLastPathComponent().path))/*.dylib; do [ -f "$lib" ] && install -m 644 -o root -g wheel "$lib" \(q(dir + "/bin/")) || true; done
        xattr -dr com.apple.quarantine \(q(HelperProtocol.helperPath)) \(q(dir + "/bin")) 2>/dev/null || true
        echo \(getuid()) > \(q(HelperProtocol.ownerFile))
        chown -R root:wheel \(q(dir)); chmod 755 \(q(dir))
        install -m 644 -o root -g wheel \(q(plistFile.path)) \(q(HelperProtocol.plistPath))
        launchctl bootstrap system \(q(HelperProtocol.plistPath))
        """
        let scriptFile = work.appendingPathComponent("install.sh")
        try script.write(to: scriptFile, atomically: true, encoding: .utf8)
        try runAsAdmin("/bin/sh " + q(scriptFile.path))
        // The daemon needs a moment to open its socket.
        for _ in 0..<40 {
            if await send(.init(cmd: "ping"), timeout: 2) != nil { return }
            try await Task.sleep(nanoseconds: 250_000_000)
        }
        throw LinkError(L("Помощник установлен, но не отвечает. Подробности: /var/log/com.slmtune.helper.log"))
    }

    static func uninstall() throws {
        let script = """
        launchctl bootout system/\(HelperProtocol.label) 2>/dev/null; rm -f '\(HelperProtocol.plistPath)' '\(HelperProtocol.helperPath)' '\(HelperProtocol.socketPath)'; \
        pfctl -a '\(HelperProtocol.pfAnchor)' -F all 2>/dev/null; rm -rf '\(HelperProtocol.supportDir)'
        """
        try runAsAdmin(script)
    }

    /// macOS's own password dialog (AppleScript "with administrator privileges").
    static func runAsAdmin(_ shell: String) throws {
        let esc = shell.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "\"", with: "\\\"")
        let source = "do shell script \"\(esc)\" with administrator privileges with prompt \"\(L("SLMtune устанавливает помощник для TUN, системного прокси и kill switch."))\""
        var err: NSDictionary?
        guard let s = NSAppleScript(source: source) else { throw LinkError("AppleScript") }
        s.executeAndReturnError(&err)
        if let err {
            let code = err[NSAppleScript.errorNumber] as? Int ?? 0
            if code == -128 { throw LinkError(L("Отменено.")) }
            throw LinkError(err[NSAppleScript.errorMessage] as? String ?? L("Не удалось получить права администратора."))
        }
    }
}
