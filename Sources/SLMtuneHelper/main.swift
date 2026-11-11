// SLMtune helper: a small root daemon (LaunchDaemon com.slmtune.helper), installed once with the admin password.
// It does only what needs root: runs sing-box with a TUN, switches the system proxy, loads the pf kill switch,
// flushes the DNS cache. Commands come from the owner's app over a Unix socket; see HelperProtocol.
import Darwin
import Foundation
@testable import SLMShared

setvbuf(stdout, nil, _IOLBF, 0)
func log(_ s: String) { print("\(Date()) \(s)") }

// MARK: owner

func ownerUid() -> uid_t? {
    guard let s = try? String(contentsOfFile: HelperProtocol.ownerFile, encoding: .utf8),
          let n = UInt32(s.trimmingCharacters(in: .whitespacesAndNewlines)) else { return nil }
    return n
}

func home(of uid: uid_t) -> String {
    guard let pw = getpwuid(uid) else { return "/var/empty" }
    return String(cString: pw.pointee.pw_dir)
}

// MARK: running tools

@discardableResult
func run(_ path: String, _ args: [String], input: String? = nil) -> (Int32, String) {
    let p = Process()
    p.executableURL = URL(fileURLWithPath: path)
    p.arguments = args
    let out = Pipe()
    p.standardOutput = out
    p.standardError = out
    let inPipe = Pipe()
    if input != nil { p.standardInput = inPipe }
    do { try p.run() } catch { return (-1, "\(error)") }
    if let input {
        inPipe.fileHandleForWriting.write(Data(input.utf8))
        try? inPipe.fileHandleForWriting.close()
    }
    let data = out.fileHandleForReading.readDataToEndOfFile()
    p.waitUntilExit()
    return (p.terminationStatus, String(decoding: data, as: UTF8.self))
}

// MARK: sing-box

final class SingBox {
    private var process: Process?
    var running: Bool { process?.isRunning == true }

    func start(config: String, owner: uid_t) throws {
        stop()
        let fm = FileManager.default
        try fm.createDirectory(atPath: HelperProtocol.runDir, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o755])
        let clean = try HelperProtocol.sanitize(config: config, userHome: home(of: owner))
        let cfg = HelperProtocol.runDir + "/config.json"
        fm.createFile(atPath: cfg, contents: Data(clean.utf8), attributes: [.posixPermissions: 0o600])
        // The log is the app's to read (domains, no passwords).
        fm.createFile(atPath: HelperProtocol.tunLogPath, contents: Data(), attributes: [.posixPermissions: 0o644])
        let check = run(HelperProtocol.singBoxPath, ["check", "-c", cfg])
        if check.0 != 0 { throw HelperError(check.1.trimmingCharacters(in: .whitespacesAndNewlines)) }
        let p = Process()
        p.executableURL = URL(fileURLWithPath: HelperProtocol.singBoxPath)
        p.arguments = ["run", "-c", cfg, "-D", HelperProtocol.runDir, "--disable-color"]
        p.standardOutput = FileHandle.nullDevice
        p.standardError = FileHandle(forWritingAtPath: HelperProtocol.tunLogPath) ?? FileHandle.nullDevice
        try p.run()
        process = p
        // Ready when the log says so (or it died).
        let deadline = Date().addingTimeInterval(15)
        while Date() < deadline {
            if !p.isRunning { break }
            if let t = try? String(contentsOfFile: HelperProtocol.tunLogPath, encoding: .utf8), t.contains("sing-box started") { return }
            usleep(150_000)
        }
        let tail = (try? String(contentsOfFile: HelperProtocol.tunLogPath, encoding: .utf8)).map { String($0.suffix(1500)) } ?? ""
        stop()
        throw HelperError(tail.isEmpty ? "sing-box did not start" : tail)
    }

    func stop() {
        guard let p = process else { return }
        if p.isRunning {
            p.interrupt()
            let deadline = Date().addingTimeInterval(5)
            while p.isRunning && Date() < deadline { usleep(100_000) }
            if p.isRunning { kill(p.processIdentifier, SIGKILL) }
        }
        process = nil
        try? FileManager.default.removeItem(atPath: HelperProtocol.runDir + "/config.json")
    }
}

// MARK: system proxy

func networkServices() -> [String] {
    let (_, out) = run("/usr/sbin/networksetup", ["-listallnetworkservices"])
    return out.split(separator: "\n").dropFirst().map(String.init).filter { !$0.hasPrefix("*") && !$0.isEmpty }
}

func setProxy(on: Bool, port: Int) {
    let bypass = ["localhost", "127.0.0.1", "*.local", "169.254/16", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
    for svc in networkServices() {
        if on {
            run("/usr/sbin/networksetup", ["-setwebproxy", svc, "127.0.0.1", "\(port)"])
            run("/usr/sbin/networksetup", ["-setsecurewebproxy", svc, "127.0.0.1", "\(port)"])
            run("/usr/sbin/networksetup", ["-setsocksfirewallproxy", svc, "127.0.0.1", "\(port)"])
            run("/usr/sbin/networksetup", ["-setproxybypassdomains", svc] + bypass)
        } else {
            run("/usr/sbin/networksetup", ["-setwebproxystate", svc, "off"])
            run("/usr/sbin/networksetup", ["-setsecurewebproxystate", svc, "off"])
            run("/usr/sbin/networksetup", ["-setsocksfirewallproxystate", svc, "off"])
        }
    }
}

// MARK: kill switch (pf)

let ksStateFile = HelperProtocol.supportDir + "/killswitch"

func killSwitchState() -> String {
    (try? String(contentsOfFile: ksStateFile, encoding: .utf8))?.split(separator: "\n").first.map(String.init) ?? "off"
}

func setKillSwitch(scope: String, servers: [String], allowLan: Bool, blocked: [String]) throws {
    if scope == "off" {
        run("/sbin/pfctl", ["-a", HelperProtocol.pfAnchor, "-F", "all"])
        if let t = try? String(contentsOfFile: ksStateFile, encoding: .utf8), let token = t.split(separator: "\n").dropFirst().first {
            run("/sbin/pfctl", ["-X", String(token)])
        }
        try? FileManager.default.removeItem(atPath: ksStateFile)
        return
    }
    guard scope == "all" || scope == "selected" else { throw HelperError("unknown scope") }
    let rules = MacRules.pfRules(scope: scope, servers: servers, allowLan: allowLan, blockedAddresses: blocked)
    let load = run("/sbin/pfctl", ["-a", HelperProtocol.pfAnchor, "-f", "-"], input: rules)
    if load.0 != 0 { throw HelperError("pfctl: " + load.1) }
    // Enable pf with a reference token (released when the kill switch is turned off).
    var token = ""
    if !killSwitchState().hasPrefix("all") && !killSwitchState().hasPrefix("selected") {
        let (_, out) = run("/sbin/pfctl", ["-E"])
        token = out.split(separator: "\n").first { $0.contains("Token") }.flatMap { $0.split(separator: ":").last }
            .map { $0.trimmingCharacters(in: .whitespaces) } ?? ""
    } else if let t = try? String(contentsOfFile: ksStateFile, encoding: .utf8) {
        token = t.split(separator: "\n").dropFirst().first.map(String.init) ?? ""
    }
    try "\(scope)\n\(token)\n".write(toFile: ksStateFile, atomically: true, encoding: .utf8)
}

// MARK: commands

let singBox = SingBox()

func handle(_ r: HelperProtocol.Request, owner: uid_t) -> HelperProtocol.Reply {
    do {
        switch r.cmd {
        case "ping":
            return .init(ok: true, running: singBox.running, killSwitch: killSwitchState())
        case "start":
            guard let c = r.config else { throw HelperError("no config") }
            try singBox.start(config: c, owner: owner)
            return .init(ok: true, running: true, killSwitch: killSwitchState())
        case "stop":
            singBox.stop()
            return .init(ok: true, killSwitch: killSwitchState())
        case "proxy":
            let port = r.port ?? 0
            guard (1...65535).contains(port) || r.on == false else { throw HelperError("bad port") }
            setProxy(on: r.on ?? false, port: port)
            return .init(ok: true, running: singBox.running)
        case "killswitch":
            let servers = (r.servers ?? []).filter(MacRules.isAddress)
            try setKillSwitch(scope: r.scope ?? "off", servers: servers, allowLan: r.allowLan ?? true, blocked: r.blocked ?? [])
            return .init(ok: true, running: singBox.running, killSwitch: killSwitchState())
        case "flushdns":
            run("/usr/bin/dscacheutil", ["-flushcache"])
            run("/usr/bin/killall", ["-HUP", "mDNSResponder"])
            return .init(ok: true)
        default:
            throw HelperError("unknown command")
        }
    } catch {
        return .init(ok: false, message: error.localizedDescription, running: singBox.running, killSwitch: killSwitchState())
    }
}

// MARK: socket

func serve() {
    unlink(HelperProtocol.socketPath)
    let fd = socket(AF_UNIX, SOCK_STREAM, 0)
    guard fd >= 0 else { log("socket failed"); exit(1) }
    var addr = sockaddr_un()
    addr.sun_family = sa_family_t(AF_UNIX)
    let path = HelperProtocol.socketPath
    withUnsafeMutableBytes(of: &addr.sun_path) { raw in
        let bytes = Array(path.utf8.prefix(raw.count - 1))
        raw.copyBytes(from: bytes + [0])
    }
    let len = socklen_t(MemoryLayout<sockaddr_un>.size)
    guard withUnsafePointer(to: &addr, { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(fd, $0, len) } }) == 0 else {
        log("bind failed: \(errno)"); exit(1)
    }
    // Anyone may connect; every request is checked against the owner's uid (getpeereid).
    chmod(path, 0o666)
    listen(fd, 8)
    log("listening on \(path)")
    while true {
        let c = accept(fd, nil, nil)
        if c < 0 { continue }
        var uid: uid_t = 0, gid: gid_t = 0
        guard getpeereid(c, &uid, &gid) == 0, uid == 0 || uid == ownerUid() else {
            let deny = (try? JSONEncoder().encode(HelperProtocol.Reply(ok: false, message: "not the owner"))) ?? Data()
            _ = deny.withUnsafeBytes { write(c, $0.baseAddress, $0.count) }
            close(c)
            continue
        }
        let owner = ownerUid() ?? uid
        DispatchQueue.global().async {
            defer { close(c) }
            var buf = Data()
            var chunk = [UInt8](repeating: 0, count: 65536)
            while true {
                let n = read(c, &chunk, chunk.count)
                if n <= 0 { break }
                buf.append(contentsOf: chunk[0..<n])
                if buf.count > 8 * 1024 * 1024 { return }
                if chunk[0..<n].contains(10) { break }
            }
            guard let line = buf.split(separator: 10).first,
                  let req = try? JSONDecoder().decode(HelperProtocol.Request.self, from: Data(line)) else { return }
            // One command at a time: start/stop/pf must not interleave.
            let reply = queue.sync { handle(req, owner: owner) }
            var out = (try? JSONEncoder().encode(reply)) ?? Data()
            out.append(10)
            _ = out.withUnsafeBytes { write(c, $0.baseAddress, $0.count) }
        }
    }
}

let queue = DispatchQueue(label: "helper.commands")
signal(SIGPIPE, SIG_IGN)
signal(SIGTERM) { _ in singBox.stop(); exit(0) }
serve()
