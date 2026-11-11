import SwiftUI
@testable import SLMShared

enum NavSection: String, CaseIterable, Identifiable {
    case home, servers, subscriptions, routing, services, killSwitch, cascade, zapret, myServers, connections, traffic, log, cores, settings
    var id: String { rawValue }

    var title: String {
        switch self {
        case .home: return L("Главная")
        case .servers: return L("Серверы")
        case .subscriptions: return L("Подписки")
        case .routing: return L("Маршруты")
        case .services: return L("ИИ, игры и звонки")
        case .killSwitch: return "Kill switch"
        case .cascade: return L("Каскад")
        case .zapret: return "Zapret"
        case .myServers: return L("Мои серверы")
        case .connections: return L("Соединения")
        case .traffic: return L("Трафик")
        case .log: return L("Журнал")
        case .cores: return L("Ядра")
        case .settings: return L("Настройки")
        }
    }

    var icon: String {
        switch self {
        case .home: return "power"
        case .servers: return "server.rack"
        case .subscriptions: return "arrow.triangle.2.circlepath"
        case .routing: return "arrow.triangle.branch"
        case .services: return "sparkles"
        case .killSwitch: return "lock.shield"
        case .cascade: return "point.3.connected.trianglepath.dotted"
        case .zapret: return "bolt.horizontal"
        case .myServers: return "externaldrive.connected.to.line.below"
        case .connections: return "list.bullet.rectangle"
        case .traffic: return "chart.bar"
        case .log: return "text.alignleft"
        case .cores: return "cpu"
        case .settings: return "gearshape"
        }
    }
}

struct MainView: View {
    @EnvironmentObject var state: AppState
    @State private var section: NavSection? = .home

    var body: some View {
        NavigationSplitView {
            List(selection: $section) {
                ForEach(NavSection.allCases) { s in
                    Label(s.title, systemImage: s.icon).tag(s)
                }
            }
            .navigationSplitViewColumnWidth(min: 200, ideal: 220)
            .safeAreaInset(edge: .bottom) {
                HStack(spacing: 8) {
                    Circle().fill(statusColor).frame(width: 8, height: 8)
                    Text(statusText).font(.caption).foregroundStyle(Slm.text2)
                    Spacer()
                }
                .padding(12)
            }
        } detail: {
            Group {
                switch section ?? .home {
                case .home: HomeView()
                case .servers: ServersView()
                case .subscriptions: SubscriptionsView()
                case .routing: RoutingView()
                case .services: ServicesView()
                case .killSwitch: KillSwitchView()
                case .cascade: CascadeView()
                case .zapret: ZapretView()
                case .myServers: MyServersView()
                case .connections: ConnectionsView()
                case .traffic: TrafficView()
                case .log: LogView()
                case .cores: CoresView()
                case .settings: SettingsView()
                }
            }
            .background(Slm.ink)
            .overlay(alignment: .bottom) {
                if let t = state.toast {
                    Text(t).padding(.horizontal, 16).padding(.vertical, 10)
                        .background(Slm.card, in: Capsule()).overlay(Capsule().stroke(Slm.line))
                        .padding(.bottom, 18).transition(.move(edge: .bottom).combined(with: .opacity))
                }
            }
            .animation(.easeOut(duration: 0.2), value: state.toast)
        }
        .sheet(item: Binding(get: { state.pendingSubscriptionURL.map { IdentifiedString(value: $0) } },
                             set: { state.pendingSubscriptionURL = $0?.value })) { s in
            AddSubscriptionSheet(url: s.value)
        }
        .sheet(item: Binding(get: { state.availableUpdate.map { IdentifiedString(value: $0.version) } },
                             set: { if $0 == nil { state.availableUpdate = nil } })) { _ in
            if let u = state.availableUpdate { UpdateSheet(update: u) }
        }
    }

    private var statusColor: Color {
        switch state.status { case .on: return Slm.ok; case .off: return Slm.text3; default: return Slm.warn }
    }

    private var statusText: String {
        switch state.status {
        case .on: return L("Подключено")
        case .off: return state.killSwitchActive != "off" ? L("Отключено · kill switch") : L("Отключено")
        case .connecting: return L("Подключение…")
        case .stopping: return L("Отключение…")
        }
    }
}

struct IdentifiedString: Identifiable { let value: String; var id: String { value } }

struct AddSubscriptionSheet: View {
    @EnvironmentObject var state: AppState
    @Environment(\.dismiss) private var dismiss
    let url: String
    @State private var name = ""

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text(L("Добавить подписку?")).font(.headline)
            Text(url).font(.system(.caption, design: .monospaced)).foregroundStyle(Slm.text2).lineLimit(2)
            TextField(L("Название (необязательно)"), text: $name)
            HStack {
                Spacer()
                Button(L("Отмена")) { dismiss() }
                Button(L("Добавить")) {
                    let n = name
                    Task { await state.addSubscription(url: url, name: n) }
                    dismiss()
                }.keyboardShortcut(.defaultAction)
            }
        }
        .padding(22).frame(width: 460)
    }
}

struct UpdateSheet: View {
    @EnvironmentObject var state: AppState
    @Environment(\.dismiss) private var dismiss
    let update: AppUpdater.Update

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text(L("Вышла SLMtune %@", update.version)).font(.headline)
            ScrollView { Text(update.notes).font(.callout).frame(maxWidth: .infinity, alignment: .leading) }.frame(height: 220)
            Text(L("VPN отключится на несколько секунд, настройки и серверы сохранятся. Установщик проверяется по SHA-256 с GitHub."))
                .font(.caption).foregroundStyle(Slm.text2)
            HStack {
                Button(L("Пропустить версию")) { state.settings.updateSkipped = update.version; state.availableUpdate = nil; dismiss() }
                Spacer()
                Button(L("Позже")) { state.availableUpdate = nil; dismiss() }
                Button(L("Установить")) { Task { await state.installUpdate(update) } }.keyboardShortcut(.defaultAction)
            }
        }
        .padding(22).frame(width: 520)
    }
}
