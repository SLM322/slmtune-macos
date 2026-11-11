import SwiftUI
@testable import SLMShared

struct HomeView: View {
    @EnvironmentObject var state: AppState
    @EnvironmentObject var monitor: ClashMonitor

    var body: some View {
        Page(title: "SLMtune", subtitle: state.status == .on ? state.chain : L("VPN для macOS: sing-box, Xray, mihomo, Hysteria 2, NaiveProxy, Tor и TrustTunnel в одном окне.")) {
            HStack(alignment: .top, spacing: 14) {
                connectCard
                VStack(spacing: 14) {
                    modeCard
                    quickCard
                }
                .frame(width: 330)
            }
            if state.status == .on { speedCard }
            if !state.helperInstalled && (state.settings.mode != .local || state.settings.killSwitch) { helperCard }
            if let e = state.lastError, state.status == .off {
                Card(title: L("Не удалось подключиться")) { Text(e).foregroundStyle(Slm.err).textSelection(.enabled) }
            }
        }
    }

    private var connectCard: some View {
        Card {
            VStack(alignment: .leading, spacing: 16) {
                Button { state.toggle() } label: {
                    HStack(spacing: 10) {
                        Image(systemName: state.status == .on ? "stop.fill" : "play.fill")
                        Text(buttonTitle).font(.system(size: 18, weight: .bold))
                    }
                    .frame(maxWidth: .infinity, minHeight: 58)
                    .foregroundStyle(.white)
                    .background(state.status == .off ? AnyShapeStyle(Slm.gradient) : AnyShapeStyle(Color.white.opacity(0.08)),
                                in: RoundedRectangle(cornerRadius: 14))
                }
                .buttonStyle(.plain)
                .disabled(state.status == .stopping)

                Picker(L("Сервер"), selection: Binding(get: { state.settings.activeId }, set: { id in
                    if let s = state.settings.server(id) { state.select(s) }
                })) {
                    ForEach(state.settings.servers) { s in Text("\(s.title) · \(ShareLinks.describe(s))").tag(s.id) }
                }
                if let s = state.activeServer {
                    HStack(spacing: 8) {
                        Pill(text: ShareLinks.describe(s), color: Slm.accent2)
                        Pill(text: ShareLinks.hasUdp(s) ? L("UDP через VPN") : L("без UDP"), color: ShareLinks.hasUdp(s) ? Slm.ok : Slm.warn)
                        if !Outbounds.hops(state.settings, s).isEmpty { Pill(text: L("каскад"), color: Slm.accent2) }
                        if let since = state.connectedSince {
                            Spacer()
                            Text(since, style: .timer).font(.caption.monospacedDigit()).foregroundStyle(Slm.text2)
                        }
                    }
                }
                HStack {
                    Button(L("Из буфера")) { state.pasteFromClipboard() }
                    Button(L("QR с экрана")) { state.importFromScreen() }
                    Button(L("Пинг")) { Task { await state.pingAll() } }
                }
            }
        }
    }

    private var buttonTitle: String {
        switch state.status {
        case .off: return L("ПОДКЛЮЧИТЬ")
        case .on: return L("ОТКЛЮЧИТЬ")
        case .connecting: return L("ПОДКЛЮЧЕНИЕ…")
        case .stopping: return L("ОТКЛЮЧЕНИЕ…")
        }
    }

    private var modeCard: some View {
        Card(title: L("Режим")) {
            Picker("", selection: $state.settings.mode) {
                ForEach(ConnectMode.allCases) { m in Text(state.modeTitle(m)).tag(m) }
            }
            .pickerStyle(.radioGroup)
            .labelsHidden()
            Text(modeNote).font(.caption).foregroundStyle(Slm.text2).fixedSize(horizontal: false, vertical: true)
        }
    }

    private var modeNote: String {
        switch state.settings.mode {
        case .tun: return L("Весь трафик Mac, правила по программам, игры и звонки по UDP. Нужен помощник.")
        case .proxy: return L("Браузеры и программы, которые слушают системный прокси. Без прав администратора, если помощник не установлен — macOS спросит пароль.")
        case .local: return L("Только 127.0.0.1:%d — для программ, где прокси указан вручную.", state.settings.mixedPort)
        }
    }

    private var quickCard: some View {
        Card(title: L("Быстро")) {
            Toggle(L("ИИ через VPN"), isOn: $state.settings.aiViaVpn)
            Toggle(L("Звонки через VPN"), isOn: $state.settings.callsViaVpn)
            Toggle(L("Игры напрямую (TUN)"), isOn: $state.settings.gameMode)
            Toggle("Kill switch", isOn: $state.settings.killSwitch)
            Toggle(L("Zapret для выбранных сайтов"), isOn: $state.settings.zapretOn)
            Picker(L("Пресет"), selection: $state.settings.preset) {
                Text(L("Все сайты через VPN")).tag(Preset.all)
                Text(L("Все, кроме российских")).tag(Preset.exceptRu)
                Text(L("Только заблокированные")).tag(Preset.blocked)
            }
        }
    }

    private var speedCard: some View {
        Card(title: L("Скорость")) {
            HStack(spacing: 24) {
                Label("\(human(monitor.down))/\(L("с"))", systemImage: "arrow.down").foregroundStyle(Slm.ok)
                Label("\(human(monitor.up))/\(L("с"))", systemImage: "arrow.up").foregroundStyle(Slm.accent2)
                Spacer()
                Text(L("всего ↓ %@  ↑ %@", human(monitor.totalDown), human(monitor.totalUp))).foregroundStyle(Slm.text2)
            }
            .font(.callout.monospacedDigit())
            SpeedGraph(points: monitor.history).frame(height: 70)
        }
    }

    private var helperCard: some View {
        Card(title: L("Нужен помощник"), note: L("TUN, системный прокси без пароля и kill switch делает небольшая служба с правами администратора. Ставится один раз: macOS спросит пароль.")) {
            Button(L("Установить помощник")) { Task { await state.installHelper() } }
        }
    }
}

/// Down (green) and up (magenta) over the last two minutes, on one scale.
struct SpeedGraph: View {
    let points: [(down: Int64, up: Int64)]

    var body: some View {
        GeometryReader { g in
            let maxV = max(1024, points.map { max($0.down, $0.up) }.max() ?? 1)
            let step = g.size.width / 119
            ZStack {
                ForEach(0..<3) { i in
                    Path { p in let y = g.size.height * CGFloat(i) / 3; p.move(to: .init(x: 0, y: y)); p.addLine(to: .init(x: g.size.width, y: y)) }
                        .stroke(Slm.line)
                }
                line(points.map { $0.down }, maxV, step, g.size).stroke(Slm.ok, lineWidth: 1.6)
                line(points.map { $0.up }, maxV, step, g.size).stroke(Slm.accent2, lineWidth: 1.2)
            }
        }
    }

    private func line(_ v: [Int64], _ maxV: Int64, _ step: CGFloat, _ size: CGSize) -> Path {
        Path { p in
            let start = 120 - v.count
            for (i, x) in v.enumerated() {
                let pt = CGPoint(x: CGFloat(start + i) * step, y: size.height - CGFloat(x) / CGFloat(maxV) * (size.height - 2) - 1)
                i == 0 ? p.move(to: pt) : p.addLine(to: pt)
            }
        }
    }
}
