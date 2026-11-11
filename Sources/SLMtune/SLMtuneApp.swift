import AppKit
import SwiftUI
@testable import SLMShared

@main
struct SLMtuneApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) var delegate
    @StateObject private var state = AppState()

    var body: some Scene {
        Window("SLMtune", id: "main") {
            MainView()
                .environmentObject(state)
                .environmentObject(state.monitor)
                .frame(minWidth: 980, minHeight: 640)
                .preferredColorScheme(.dark)
                .tint(Slm.accent)
                .onOpenURL { url in state.importText(url.absoluteString) }
                .onAppear { delegate.state = state }
        }
        .windowStyle(.hiddenTitleBar)
        .commands {
            CommandGroup(after: .pasteboard) {
                Button(L("Добавить из буфера")) { state.pasteFromClipboard() }.keyboardShortcut("v", modifiers: [.command, .shift])
                Button(L("Считать QR с экрана")) { state.importFromScreen() }.keyboardShortcut("q", modifiers: [.command, .shift])
            }
            CommandMenu("VPN") {
                Button(state.status == .off ? L("Подключить") : L("Отключить")) { state.toggle() }.keyboardShortcut(.return, modifiers: .command)
            }
        }

        MenuBarExtra {
            MenuBarContent().environmentObject(state)
        } label: {
            Image(systemName: state.status == .on ? "shield.lefthalf.filled" : state.status == .off ? "shield" : "shield.slash")
        }
    }
}

final class AppDelegate: NSObject, NSApplicationDelegate {
    weak var state: AppState?

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { false }

    /// Quitting waits for the cores to stop and the system proxy to be put back.
    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        guard let state else { return .terminateNow }
        Task { @MainActor in
            await state.shutdown()
            NSApp.reply(toApplicationShouldTerminate: true)
        }
        return .terminateLater
    }

    func applicationDidFinishLaunching(_ notification: Notification) {
        // Started at login: only the menu bar icon, no window.
        if CommandLine.arguments.contains("--autostart") {
            NSApp.windows.forEach { $0.close() }
        }
    }
}

/// The menu bar icon's menu: connect, server, mode, quick switches.
struct MenuBarContent: View {
    @EnvironmentObject var state: AppState
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        Button(state.status == .off ? L("Подключить") : L("Отключить")) { state.toggle() }
        if let s = state.activeServer { Text(s.title) }
        if state.status == .on { Text(state.chain) }
        Divider()
        Menu(L("Сервер")) {
            ForEach(state.settings.servers) { s in
                Button((s.id == state.settings.activeId ? "✓ " : "") + s.title) { state.select(s) }
            }
        }
        Menu(L("Режим")) {
            ForEach(ConnectMode.allCases) { m in
                Button((state.settings.mode == m ? "✓ " : "") + state.modeTitle(m)) { state.settings.mode = m }
            }
        }
        Toggle(L("ИИ через VPN"), isOn: $state.settings.aiViaVpn)
        Toggle(L("Kill switch"), isOn: $state.settings.killSwitch)
        Toggle("Zapret", isOn: $state.settings.zapretOn)
        if state.killSwitchActive != "off", state.status == .off {
            Button(L("Снять блокировку kill switch")) { Task { await state.setKillSwitch(off: true) } }
        }
        Divider()
        Button(L("Добавить из буфера")) { state.pasteFromClipboard() }
        Button(L("Считать QR с экрана")) { state.importFromScreen() }
        Divider()
        Button(L("Открыть окно")) {
            openWindow(id: "main")
            NSApp.activate(ignoringOtherApps: true)
        }
        Button(L("Выход")) { NSApp.terminate(nil) }.keyboardShortcut("q")
    }
}
