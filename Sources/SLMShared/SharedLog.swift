import Foundation

/// The log the app shows (Журнал): files in the App Group, written by the extension.
/// sing-box writes singbox.log itself (log.output), the extra cores go to core.log, Tor to tor.log.
enum SharedLog {
    static var dir: URL {
        let u = AppGroup.container.appendingPathComponent("logs", isDirectory: true)
        try? FileManager.default.createDirectory(at: u, withIntermediateDirectories: true)
        return u
    }
    static var singBoxLogFile: URL { dir.appendingPathComponent("singbox.log") }
    static var coreLogFile: URL { dir.appendingPathComponent("core.log") }
    static var torLogFile: URL { dir.appendingPathComponent("tor.log") }
    static var all: [URL] { [singBoxLogFile, coreLogFile, torLogFile] }

    private static let queue = DispatchQueue(label: "slmtune.log")
    private static let maxSize = 512 * 1024

    /// Appends a timestamped line to core.log.
    static func append(_ tag: String, _ line: String) {
        let stamp = ISO8601DateFormatter.string(from: Date(), timeZone: .current, formatOptions: [.withTime, .withColonSeparatorInTime])
        let data = Data("\(stamp) [\(tag)] \(line)\n".utf8)
        queue.async {
            let url = coreLogFile
            if let h = try? FileHandle(forWritingTo: url) {
                h.seekToEndOfFile()
                h.write(data)
                try? h.close()
            } else {
                try? data.write(to: url)
            }
        }
    }

    /// On tunnel start: keeps the last part of each file so they never grow without end.
    static func trim() {
        for url in all {
            guard let d = try? Data(contentsOf: url), d.count > maxSize else { continue }
            try? d.suffix(maxSize / 2).write(to: url, options: .atomic)
        }
    }

    static func clear() {
        for url in all { try? Data().write(to: url) }
    }

    /// The last `maxBytes` of every log, merged by time order of the files' lines (each line keeps its source).
    static func tail(maxBytes: Int = 200_000) -> [LogLine] {
        var lines: [LogLine] = []
        for (source, url) in [("sing-box", singBoxLogFile), ("core", coreLogFile), ("tor", torLogFile)] {
            guard let h = try? FileHandle(forReadingFrom: url) else { continue }
            let size = (try? h.seekToEnd()) ?? 0
            try? h.seek(toOffset: size > UInt64(maxBytes) ? size - UInt64(maxBytes) : 0)
            let data = (try? h.readToEnd()) ?? Data()
            try? h.close()
            for l in String(decoding: data, as: UTF8.self).split(separator: "\n") where !l.isEmpty {
                lines.append(LogLine(source: source, text: String(l)))
            }
        }
        return lines
    }
}

struct LogLine: Identifiable, Hashable {
    let id = UUID()
    let source: String
    let text: String

    var level: String {
        let t = text.uppercased()
        if t.contains("ERROR") || t.contains("FATAL") || t.contains("[ERR]") { return "error" }
        if t.contains("WARN") { return "warn" }
        return "info"
    }
}
