import Darwin
import Foundation
@testable import SLMShared

/// Starts and stops one connection: the extra cores (Xray, mihomo, TrustTunnel, Tor, Hysteria 2, NaiveProxy, tpws)
/// as user processes listening on 127.0.0.1, then sing-box in front of them — as root through the helper in TUN
/// mode, as a user process otherwise. The same chain as the Windows version.
@MainActor
final class CoreRunner {
    enum Failure: LocalizedError {
        case core(String, String)
        var errorDescription: String? {
            switch self { case .core(let name, let why): return L("%@ не запустился: %@", name, why) }
        }
    }

    private var processes: [(name: String, process: Process)] = []
    private(set) var tunViaHelper = false
    /// Called when a core dies by itself (not on stop).
    var onCrash: ((String) -> Void)?
    private var stopping = false

    var isRunning: Bool { tunViaHelper || processes.contains { $0.process.isRunning } }

    private static var pidFile: URL { AppGroup.runtimeDir.appendingPathComponent("pids") }

    /// Cores left from a crash of the app: they would hold the ports.
    static func killLeftovers() {
        guard let text = try? String(contentsOf: pidFile, encoding: .utf8) else { return }
        for line in text.split(separator: "\n") { if let pid = Int32(line) { kill(pid, SIGTERM) } }
        try? FileManager.default.removeItem(at: pidFile)
    }

    private func savePids() {
        let text = processes.map { "\($0.process.processIdentifier)" }.joined(separator: "\n")
        try? text.write(to: Self.pidFile, atomically: true, encoding: .utf8)
    }

    static func freePort() -> Int {
        let fd = socket(AF_INET, SOCK_STREAM, 0)
        defer { close(fd) }
        var a = sockaddr_in()
        a.sin_family = sa_family_t(AF_INET)
        a.sin_addr.s_addr = inet_addr("127.0.0.1")
        a.sin_port = 0
        var len = socklen_t(MemoryLayout<sockaddr_in>.size)
        _ = withUnsafePointer(to: &a) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(fd, $0, len) } }
        _ = withUnsafeMutablePointer(to: &a) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(fd, $0, &len) } }
        return Int(UInt16(bigEndian: a.sin_port))
    }

    static func portOpen(_ port: Int) -> Bool {
        let fd = socket(AF_INET, SOCK_STREAM, 0)
        defer { close(fd) }
        var a = sockaddr_in()
        a.sin_family = sa_family_t(AF_INET)
        a.sin_addr.s_addr = inet_addr("127.0.0.1")
        a.sin_port = in_port_t(UInt16(port).bigEndian)
        return withUnsafePointer(to: &a) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { connect(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) } } == 0
    }

    /// Launches a core; its output goes to core.log with its name.
    private func launch(_ name: String, _ exe: URL, _ args: [String], cwd: URL? = nil, onLine: ((String) -> Void)? = nil) throws -> Process {
        let p = Process()
        p.executableURL = exe
        p.arguments = args
        p.currentDirectoryURL = cwd ?? exe.deletingLastPathComponent()
        var env = ProcessInfo.processInfo.environment
        env["DYLD_LIBRARY_PATH"] = exe.deletingLastPathComponent().path
        p.environment = env
        let pipe = Pipe()
        p.standardOutput = pipe
        p.standardError = pipe
        pipe.fileHandleForReading.readabilityHandler = { h in
            let d = h.availableData
            guard !d.isEmpty else { h.readabilityHandler = nil; return }
            for line in String(decoding: d, as: UTF8.self).split(separator: "\n") {
                SharedLog.append(name, String(line))
                onLine?(String(line))
            }
        }
        p.terminationHandler = { [weak self] proc in
            Task { @MainActor in
                guard let self, !self.stopping, self.processes.contains(where: { $0.process === proc }) else { return }
                self.onCrash?(L("%@ завершился (код %d).", name, proc.terminationStatus))
            }
        }
        try p.run()
        processes.append((name, p))
        savePids()
        return p
    }

    private func waitPort(_ port: Int, _ p: Process, _ name: String, seconds: Double = 15) async throws {
        let deadline = Date().addingTimeInterval(seconds)
        while Date() < deadline {
            if !p.isRunning { throw Failure.core(name, L("процесс завершился — подробности в журнале")) }
            if Self.portOpen(port) { return }
            try await Task.sleep(nanoseconds: 150_000_000)
        }
        throw Failure.core(name, L("не открыл порт за %d с", Int(seconds)))
    }

    private func write(_ text: String, _ name: String) throws -> URL {
        let u = AppGroup.runtimeDir.appendingPathComponent(name)
        try SettingsFile.writePrivate(text, to: u)
        return u
    }

    private func core(_ c: CoreName) throws -> URL {
        guard let p = Cores.path(c) else { throw Failure.core(c.title, L("ядро не найдено в программе")) }
        return p
    }

    // MARK: start / stop

    struct Started { let description: String; let mixedPort: Int }

    func start(_ s: AppSettings, server: Server, zapretOnly: Bool = false, progress: @escaping (String) -> Void) async throws -> Started {
        await stop()
        stopping = false
        SharedLog.trim()
        var official: Set<Engine> = []
        if s.protocols.hysteriaOfficial { official.insert(.hysteria) }
        if s.protocols.naiveOfficial { official.insert(.naive) }
        Engines.official = official

        // 1. Extra cores, one SOCKS port each.
        var ports: [String: Int] = [:]
        var names: [String] = []
        let backends = zapretOnly ? [] : Engines.backends(s, server)
        // mihomo runs all its servers in one process.
        var mihomoEntries: [(server: Server, port: Int)] = []
        for b in backends {
            guard let e = Engines.engine(b) else { continue }
            let port = Self.freePort()
            ports[b.id] = port
            switch e {
            case .mihomo:
                mihomoEntries.append((b, port))
            case .xray:
                let f = try write(Engines.xrayConfig(b, port: port, logLevel: s.logLevel), "xray-\(port).json")
                let p = try launch("xray", try core(.xray), ["run", "-c", f.path])
                try await waitPort(port, p, "Xray")
            case .trusttunnel:
                let f = try write(Engines.ttConfig(b, port: port), "trusttunnel-\(port).toml")
                let p = try launch("trusttunnel", try core(.trusttunnel), ["-c", f.path, "-l", "info"])
                try await waitPort(port, p, "TrustTunnel", seconds: 30)
            case .hysteria:
                var ca: String? = nil
                if !b.param("cert").isEmpty { ca = try write(b.param("cert"), "hy2-ca-\(port).pem").path }
                let f = try write(Engines.hysteriaConfig(b, port: port, caFile: ca, ps: s.protocols), "hysteria-\(port).json")
                let p = try launch("hysteria", try core(.hysteria), ["client", "-c", f.path, "--disable-update-check"])
                try await waitPort(port, p, "Hysteria 2", seconds: 25)
            case .naive:
                let f = try write(Engines.naiveConfig(b, port: port), "naive-\(port).json")
                let p = try launch("naive", try core(.naive), [f.path])
                try await waitPort(port, p, "NaiveProxy")
            case .tor:
                progress(L("Tor строит цепочку — до двух минут при первом запуске…"))
                let data = AppGroup.container.appendingPathComponent("tor-data", isDirectory: true)
                try? FileManager.default.createDirectory(at: data, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
                let bridges = try Engines.torBridges(b)
                let args = Engines.torArgumentsMac(socksPort: port, dataDir: data.path, logFile: SharedLog.torLogFile.path, bridges: bridges,
                                                   pt: Cores.torPluggableTransports.path, geoip: Cores.torGeoIP.path)
                let ready = Flag()
                let p = try launch("tor", try core(.tor), args) { line in if line.contains("Bootstrapped 100%") { ready.set() } }
                let deadline = Date().addingTimeInterval(150)
                while !ready.value, Date() < deadline {
                    if !p.isRunning { throw Failure.core("Tor", L("процесс завершился — подробности в журнале")) }
                    try await Task.sleep(nanoseconds: 300_000_000)
                }
                if !ready.value { throw Failure.core("Tor", L("не подключился к сети Tor за 150 с. Попробуйте другие мосты.")) }
            }
            names.append(e.title)
        }
        if !mihomoEntries.isEmpty {
            let f = try write(Engines.mihomoConfig(mihomoEntries, logLevel: s.logLevel), "mihomo.yaml")
            let dir = AppGroup.runtimeDir.appendingPathComponent("mihomo", isDirectory: true)
            try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
            let p = try launch("mihomo", try core(.mihomo), ["-d", dir.path, "-f", f.path])
            for e in mihomoEntries { try await waitPort(e.port, p, "mihomo") }
            names.append("mihomo")
        }

        // 2. Zapret (tpws as a SOCKS proxy with DPI tricks).
        var zapretPort: Int? = nil
        if s.zapretOn || zapretOnly {
            let port = Self.freePort()
            let args = ["--socks", "--bind-addr=127.0.0.1", "--port=\(port)"] + Zapret.arguments(s.zapretStrategy)
            let p = try launch("tpws", try core(.tpws), args)
            try await waitPort(port, p, "Zapret (tpws)")
            zapretPort = port
            names.append("Zapret")
        }

        // 3. sing-box in front.
        let tun = s.mode == .tun && !zapretOnly || (zapretOnly && s.mode == .tun)
        let own = ["xray", "mihomo", "trusttunnel_client", "hysteria", "naive", "tor", "lyrebird", "snowflake-client", "tpws", "SLMtune"]
        let mac = ConfigBuilder.Mac(tun: tun, zapretPort: zapretPort, ownProcesses: own, logFile: nil, zapretOnly: zapretOnly)
        let config = try ConfigBuilder.build(s, server: server, backends: ports, mac: mac)
        try? SettingsFile.writePrivate(config, to: AppGroup.lastConfigFile)
        if tun {
            guard HelperClient.isInstalled else { throw LinkError(L("Для режима TUN нужен помощник: «Настройки → Помощник → Установить».")) }
            guard let r = await HelperClient.send(.init(cmd: "start").with { $0.config = config }, timeout: 40) else {
                throw LinkError(L("Помощник не отвечает. Переустановите его в настройках."))
            }
            if !r.ok { throw Failure.core("sing-box", r.message) }
            tunViaHelper = true
            _ = await HelperClient.send(.init(cmd: "flushdns"))
        } else {
            let f = try write(config, "sing-box.json")
            let work = AppGroup.workingDir
            let p = try launch("sing-box", try core(.singBox), ["run", "-c", f.path, "-D", work.path, "--disable-color"], cwd: work)
            try await waitPort(s.mixedPort, p, "sing-box")
        }
        let chain = (names + ["sing-box"]).joined(separator: " → ")
        return Started(description: chain + (tun ? " · TUN" : ""), mixedPort: s.mixedPort)
    }

    func stop() async {
        stopping = true
        if tunViaHelper {
            _ = await HelperClient.send(.init(cmd: "stop"))
            tunViaHelper = false
        }
        for (_, p) in processes.reversed() where p.isRunning {
            p.interrupt()
        }
        let deadline = Date().addingTimeInterval(4)
        while processes.contains(where: { $0.process.isRunning }) && Date() < deadline {
            try? await Task.sleep(nanoseconds: 100_000_000)
        }
        for (_, p) in processes where p.isRunning { kill(p.processIdentifier, SIGKILL) }
        processes.removeAll()
        try? FileManager.default.removeItem(at: Self.pidFile)
        // Runtime configs hold passwords.
        if let files = try? FileManager.default.contentsOfDirectory(at: AppGroup.runtimeDir, includingPropertiesForKeys: nil) {
            for f in files where f.lastPathComponent != "mihomo" { try? FileManager.default.removeItem(at: f) }
        }
    }
}

extension HelperProtocol.Request {
    func with(_ f: (inout Self) -> Void) -> Self { var c = self; f(&c); return c }
}

/// Zapret on macOS: tpws (bol-van/zapret) as a local SOCKS proxy; strategies are tpws's own DPI tricks.
enum Zapret {
    static let strategies: [(id: String, title: String, args: [String])] = [
        ("split", "Разделение SNI (по умолчанию)", ["--split-pos=1,midsld"]),
        ("disorder", "Разделение с перестановкой", ["--split-pos=1,midsld", "--disorder"]),
        ("oob", "Разделение + OOB-байт", ["--split-pos=1", "--oob"]),
        ("tlsrec", "Разрыв TLS-записи", ["--tlsrec=sniext", "--split-pos=1,midsld"]),
        ("hostcase", "Регистр Host (HTTP) + разделение", ["--hostcase", "--split-pos=1,midsld"]),
    ]

    static func arguments(_ id: String) -> [String] { strategies.first { $0.id == id }?.args ?? strategies[0].args }
}

/// A flag set from a core's output thread and read on the main actor.
final class Flag: @unchecked Sendable {
    private let lock = NSLock()
    private var v = false
    var value: Bool { lock.lock(); defer { lock.unlock() }; return v }
    func set() { lock.lock(); v = true; lock.unlock() }
}
