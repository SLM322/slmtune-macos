import Foundation
@testable import SLMShared
import Network

/// Server ping as in the Windows version: the time of a TCP handshake to server:port, best of two.
/// Measured outside the tunnel only when the VPN is off; with it on, iOS sends the app's sockets through
/// the tunnel and the number shows the path via the current server.
enum Pinger {
    static let udpOnly: Set<String> = ["hysteria2", "hysteria", "tuic", "wireguard"]

    /// Milliseconds, or -2 when there is no answer within the timeout.
    static func tcp(host: String, port: Int, timeout: TimeInterval = 3) async -> Int {
        var best = -2
        for _ in 0..<2 {
            let ms = await once(host: host, port: port, timeout: timeout)
            if ms >= 0, best < 0 || ms < best { best = ms }
        }
        return best
    }

    private static func once(host: String, port: Int, timeout: TimeInterval) async -> Int {
        guard let p = NWEndpoint.Port(rawValue: UInt16(clamping: port)) else { return -2 }
        let conn = NWConnection(host: NWEndpoint.Host(host), port: p, using: .tcp)
        let start = DispatchTime.now()
        return await withCheckedContinuation { (cont: CheckedContinuation<Int, Never>) in
            let lock = NSLock()
            var finished = false
            func finish(_ v: Int) {
                lock.lock(); defer { lock.unlock() }
                guard !finished else { return }
                finished = true
                conn.cancel()
                cont.resume(returning: v)
            }
            conn.stateUpdateHandler = { state in
                switch state {
                case .ready: finish(Int((DispatchTime.now().uptimeNanoseconds - start.uptimeNanoseconds) / 1_000_000))
                case .failed, .cancelled: finish(-2)
                case .waiting: finish(-2)
                default: break
                }
            }
            conn.start(queue: .global())
            DispatchQueue.global().asyncAfter(deadline: .now() + timeout) { finish(-2) }
        }
    }
}
