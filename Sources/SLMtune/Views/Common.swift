import AppKit
import SwiftUI
@testable import SLMShared

/// SLMtune's palette (the Windows "ink" theme): ink background, magenta accent.
enum Slm {
    static let ink = Color(red: 0.043, green: 0.043, blue: 0.051)
    static let card = Color(red: 0.082, green: 0.082, blue: 0.094)
    static let line = Color.white.opacity(0.08)
    static let accent = Color(red: 0.82, green: 0, blue: 0.82)
    static let accent2 = Color(red: 1, green: 0.24, blue: 1)
    static let tint = Color(red: 0.18, green: 0.043, blue: 0.18)
    static let text2 = Color.white.opacity(0.62)
    static let text3 = Color.white.opacity(0.42)
    static let ok = Color(red: 0.2, green: 0.83, blue: 0.6)
    static let warn = Color(red: 0.96, green: 0.72, blue: 0.24)
    static let err = Color(red: 1, green: 0.36, blue: 0.48)
    static let gradient = LinearGradient(colors: [accent, accent2], startPoint: .leading, endPoint: .trailing)
}

/// A card with a title, as on Windows.
struct Card<Content: View>: View {
    var title: String? = nil
    var note: String? = nil
    @ViewBuilder var content: Content

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            if let title { Text(title).font(.headline) }
            if let note { Text(note).font(.callout).foregroundStyle(Slm.text2).fixedSize(horizontal: false, vertical: true) }
            content
        }
        .padding(16)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Slm.card, in: RoundedRectangle(cornerRadius: 12))
        .overlay(RoundedRectangle(cornerRadius: 12).stroke(Slm.line))
    }
}

/// A page: a title, a line under it, scrolling content.
struct Page<Content: View>: View {
    let title: String
    var subtitle: String? = nil
    @ViewBuilder var content: Content

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 14) {
                VStack(alignment: .leading, spacing: 4) {
                    Text(title).font(.system(size: 24, weight: .semibold))
                    if let subtitle { Text(subtitle).foregroundStyle(Slm.text2).fixedSize(horizontal: false, vertical: true) }
                }
                content
            }
            .padding(22)
            .frame(maxWidth: 980, alignment: .leading)
        }
        .background(Slm.ink)
    }
}

struct Pill: View {
    let text: String
    var color: Color = Slm.text2
    var body: some View {
        Text(text).font(.caption.weight(.semibold)).padding(.horizontal, 8).padding(.vertical, 3)
            .background(color.opacity(0.16), in: Capsule()).foregroundStyle(color)
    }
}

/// A multi-line list editor: one entry per line.
struct LinesEditor: View {
    @Binding var lines: [String]
    var placeholder = ""
    var height: CGFloat = 110
    @State private var text = ""

    var body: some View {
        TextEditor(text: $text)
            .font(.system(.callout, design: .monospaced))
            .frame(height: height)
            .scrollContentBackground(.hidden)
            .padding(6)
            .background(Color.black.opacity(0.25), in: RoundedRectangle(cornerRadius: 8))
            .overlay(alignment: .topLeading) {
                if text.isEmpty { Text(placeholder).foregroundStyle(Slm.text3).padding(10).allowsHitTesting(false) }
            }
            .onAppear { text = lines.joined(separator: "\n") }
            .onChange(of: text) { t in
                let l = t.split(separator: "\n").map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }
                if l != lines { lines = l }
            }
    }
}

func copyToClipboard(_ s: String) {
    NSPasteboard.general.clearContents()
    NSPasteboard.general.setString(s, forType: .string)
}

/// QR code and link of one server, in a sheet.
struct ShareSheet: View {
    let title: String
    let link: String
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        VStack(spacing: 14) {
            Text(title).font(.headline)
            if let img = ScreenQR.image(link) {
                Image(nsImage: img).interpolation(.none).resizable().frame(width: 260, height: 260)
                    .padding(10).background(Color.white, in: RoundedRectangle(cornerRadius: 10))
            }
            Text(link).font(.system(.caption, design: .monospaced)).lineLimit(4).textSelection(.enabled).frame(maxWidth: 420)
            HStack {
                Button(L("Скопировать ссылку")) { copyToClipboard(link) }
                Button(L("Закрыть")) { dismiss() }.keyboardShortcut(.defaultAction)
            }
        }
        .padding(24)
    }
}

/// Lists in the app's colours (shared with the iOS screens ported here).
struct SlmList<Content: View>: View {
    @ViewBuilder var content: () -> Content
    var body: some View {
        List { content() }
            .scrollContentBackground(.hidden)
            .background(Slm.ink)
    }
}

extension View {
    func slmRow() -> some View { listRowBackground(Slm.card) }
}

struct ShareServerView: View {
    let link: String
    var body: some View { ShareSheet(title: L("QR-код и ссылка"), link: link) }
}
