import Citadel
import Crypto
import Foundation
@testable import SLMShared
import NIOCore
import NIOSSH

/// SSH for "Мои серверы" (Citadel / SwiftNIO SSH). The app's own ed25519 key lives in the app's private
/// folder; a server's host key is pinned only after the user confirms its fingerprint, and checked on every connect.
enum SSH {
    struct Target {
        var host: String
        var port: Int
        var user: String
        var hostKey: String
        var password: String?
    }

    struct Failed: LocalizedError {
        let message: String
        init(_ m: String) { message = m }
        var errorDescription: String? { message }
    }

    // MARK: the app's key

    private static var keyFile: URL {
        let dir = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir.appendingPathComponent("ssh_ed25519.key")
    }

    static func appKey() -> Curve25519.Signing.PrivateKey {
        if let d = try? Data(contentsOf: keyFile), let k = try? Curve25519.Signing.PrivateKey(rawRepresentation: d) { return k }
        let k = Curve25519.Signing.PrivateKey()
        try? k.rawRepresentation.write(to: keyFile, options: [.atomic, .completeFileProtection])
        return k
    }

    private static func sshString(_ d: Data) -> Data {
        var n = UInt32(d.count).bigEndian
        return Data(bytes: &n, count: 4) + d
    }

    /// "ssh-ed25519 AAAA… slmtune" for authorized_keys.
    static func publicKeyLine() -> String {
        let blob = sshString(Data("ssh-ed25519".utf8)) + sshString(appKey().publicKey.rawRepresentation)
        return "ssh-ed25519 " + blob.base64EncodedString() + " slmtune"
    }

    static func fingerprint(_ keyLine: String) -> String {
        let parts = keyLine.split(separator: " ")
        guard parts.count >= 2, let blob = Data(base64Encoded: String(parts[1])) else { return keyLine }
        let digest = SHA256.hash(data: blob)
        return "SHA256:" + Data(digest).base64EncodedString().replacingOccurrences(of: "=", with: "")
    }

    private static func normalized(_ line: String) -> String { line.split(separator: " ").prefix(2).joined(separator: " ") }

    // MARK: host keys

    final class HostKeyCheck: NIOSSHClientServerAuthenticationDelegate {
        let pinned: String?
        private(set) var seen: String?
        init(pinned: String?) { self.pinned = pinned }

        func validateHostKey(hostKey: NIOSSHPublicKey, validationCompletePromise: EventLoopPromise<Void>) {
            let line = String(openSSHPublicKey: hostKey)
            seen = line
            if let pinned, SSH.normalized(line) != SSH.normalized(pinned) {
                validationCompletePromise.fail(Failed(L("Ключ сервера изменился. Если вы не переустанавливали сервер, кто-то может подменять подключение.")))
            } else {
                validationCompletePromise.succeed(())
            }
        }
    }

    /// The server's host key, for the user to confirm before anything else is sent.
    static func scan(host: String, port: Int) async throws -> String {
        let check = HostKeyCheck(pinned: nil)
        do {
            let c = try await SSHClient.connect(
                host: host, port: port,
                authenticationMethod: .passwordBased(username: "slmtune-scan", password: UUID().uuidString),
                hostKeyValidator: .custom(check), reconnect: .never)
            try? await c.close()
        } catch {
            if check.seen == nil { throw Failed(explain(error)) }
        }
        guard let key = check.seen else { throw Failed(L("Сервер не прислал ключ SSH.")) }
        return key
    }

    static func explain(_ e: Error) -> String {
        if let f = e as? Failed { return f.message }
        let m = String(describing: e).lowercased()
        if m.contains("refused") { return L("Сервер отклонил подключение: на этом порту нет SSH. Проверьте порт (обычно 22).") }
        if m.contains("timed out") || m.contains("timeout") { return L("Сервер не ответил: адрес недоступен или порт SSH закрыт файрволом хостинга.") }
        if m.contains("nodename") || m.contains("resolve") || m.contains("unknown host") { return L("Адрес сервера не найден. Проверьте, что он написан правильно.") }
        if m.contains("reset") || m.contains("closed") || m.contains("eof") { return L("Сервер оборвал подключение. Возможно, SSH блокирует провайдер — попробуйте с включённым VPN.") }
        if m.contains("auth") { return L("Сервер не принял вход: проверьте пользователя и пароль.") }
        return "SSH: " + e.localizedDescription
    }

    // MARK: running scripts

    /// Runs a bash script on the server (as root, via sudo for other users), streaming its output lines.
    /// The script travels base64-encoded in the command (in chunks through a temp file when it is large),
    /// because Citadel has no stdin for exec.
    static func run(_ t: Target, script: String, onLine: @escaping (String) -> Void) async throws -> (Int, String) {
        let check = HostKeyCheck(pinned: t.hostKey)
        let auth: SSHAuthenticationMethod = (t.password?.isEmpty == false)
            ? .passwordBased(username: t.user, password: t.password!)
            : .ed25519(username: t.user, privateKey: appKey())
        let client: SSHClient
        do {
            client = try await SSHClient.connect(host: t.host, port: t.port, authenticationMethod: auth,
                                                 hostKeyValidator: .custom(check), reconnect: .never)
        } catch {
            throw Failed(explain(error))
        }
        defer { Task { try? await client.close() } }

        let b64 = Data(script.replacingOccurrences(of: "\r\n", with: "\n").utf8).base64EncodedString()
        let bash = t.user == "root" ? "bash -s" : "sudo -n bash -s"
        let command: String
        if b64.count < 60_000 {
            command = "printf %s '\(b64)' | base64 -d | \(bash)"
        } else {
            // One argv string is limited to 128 KB on Linux: upload in pieces first.
            let tmp = "/tmp/slm-\(UUID().uuidString.prefix(8)).b64"
            _ = try await client.executeCommand(": > \(tmp) && chmod 600 \(tmp)")
            var rest = Substring(b64)
            while !rest.isEmpty {
                let chunk = rest.prefix(60_000)
                rest = rest.dropFirst(chunk.count)
                _ = try await client.executeCommand("printf %s '\(chunk)' >> \(tmp)")
            }
            command = "base64 -d \(tmp) | \(bash); rc=$?; rm -f \(tmp); exit $rc"
        }

        var output = ""
        var pending = ""
        func feed(_ buf: ByteBuffer) {
            pending += String(buffer: buf)
            while let nl = pending.firstIndex(of: "\n") {
                let line = String(pending[..<nl]).trimmingCharacters(in: CharacterSet(charactersIn: "\r"))
                pending = String(pending[pending.index(after: nl)...])
                output += line + "\n"
                onLine(line)
            }
        }
        do {
            for try await event in try await client.executeCommandStream(command) {
                switch event {
                case .stdout(let b): feed(b)
                case .stderr(let b): feed(b)
                }
            }
        } catch let failed as SSHClient.CommandFailed {
            if !pending.isEmpty { output += pending; onLine(pending) }
            return (Int(failed.exitCode), output)
        } catch {
            throw Failed(explain(error))
        }
        if !pending.isEmpty { output += pending; onLine(pending) }
        return (0, output)
    }
}
