import AppKit
import SwiftUI
@testable import SLMShared

// MARK: Маршруты

struct RoutingView: View {
    @EnvironmentObject var state: AppState
    @State private var editingRule: CustomRule?

    var body: some View {
        Page(title: L("Маршруты"), subtitle: L("Что идёт через VPN, что напрямую, что блокируется. Свои правила и правила программ проверяются раньше пресета.")) {
            Card(title: L("Пресет")) {
                Picker("", selection: $state.settings.preset) {
                    Text(L("Все сайты через VPN")).tag(Preset.all)
                    Text(L("Все, кроме российских сайтов и IP")).tag(Preset.exceptRu)
                    Text(L("Только заблокированные в России")).tag(Preset.blocked)
                }
                .pickerStyle(.radioGroup).labelsHidden()
                HStack {
                    Button(state.listsUpdating ? L("Обновляю…") : L("Обновить списки")) { Task { await state.updateLists(force: true) } }
                        .disabled(state.listsUpdating)
                    Toggle(L("Локальная сеть мимо VPN"), isOn: $state.settings.lanBypass)
                    Toggle("IPv6", isOn: $state.settings.ipv6)
                }
            }
            Card(title: L("Блокировка"), note: L("Списки MetaCubeX, обновляются раз в сутки. Работает внутри VPN: и в TUN, и через прокси.")) {
                ForEach(Lists.blocks) { b in
                    Toggle(isOn: Binding(get: { state.settings.blockLists.contains(b.id) }, set: { on in
                        if on { state.settings.blockLists.append(b.id) } else { state.settings.blockLists.removeAll { $0 == b.id } }
                    })) { Text("\(L(b.title)) — \(L(b.note))") }
                }
            }
            Card(title: L("Свои правила"), note: L("Сайты и IP: через VPN, напрямую или блок.")) {
                ForEach(state.settings.customRules) { r in
                    HStack {
                        Toggle("", isOn: Binding(get: { r.enabled }, set: { on in mutateRule(r.id) { $0.enabled = on } })).labelsHidden()
                        VStack(alignment: .leading) {
                            Text(r.name.isEmpty ? (r.domains + r.ips).prefix(3).joined(separator: ", ") : r.name)
                            Text(actionTitle(r.action) + " · " + L("%d сайтов, %d IP", r.domains.count, r.ips.count)).font(.caption).foregroundStyle(Slm.text2)
                        }
                        Spacer()
                        Button(L("Изменить")) { editingRule = r }
                        Button(role: .destructive) { state.settings.customRules.removeAll { $0.id == r.id } } label: { Image(systemName: "trash") }
                    }
                }
                Button(L("Добавить правило")) { editingRule = CustomRule() }
            }
            Card(title: L("Программы (TUN)"), note: L("Правило для программы: имя процесса, как в Мониторинге системы («Telegram», «Google Chrome»). Работает только в режиме TUN.")) {
                ForEach($state.settings.appRules) { $r in
                    HStack {
                        Toggle("", isOn: $r.enabled).labelsHidden()
                        TextField(L("Имя процесса"), text: $r.process).frame(width: 220)
                        Picker("", selection: $r.action) {
                            Text(L("через VPN")).tag("vpn")
                            Text(L("напрямую")).tag("direct")
                            Text(L("блок")).tag("block")
                        }.labelsHidden().frame(width: 140)
                        Spacer()
                        Button(role: .destructive) { state.settings.appRules.removeAll { $0.id == r.id } } label: { Image(systemName: "trash") }
                    }
                }
                HStack {
                    Button(L("Добавить программу")) { state.settings.appRules.append(AppRule()) }
                    Button(L("Выбрать приложение…")) { pickApp() }
                }
            }
            Card(title: "DNS") {
                TextField(L("DNS через VPN"), text: $state.settings.remoteDns)
                TextField(L("DNS напрямую"), text: $state.settings.directDns)
                Text(L("https://, tls://, quic:// или IP. Напрямую — для российских сайтов, через VPN — для остальных.")).font(.caption).foregroundStyle(Slm.text2)
            }
        }
        .sheet(item: $editingRule) { r in RuleSheet(rule: r) }
    }

    private func mutateRule(_ id: String, _ f: (inout CustomRule) -> Void) {
        if let i = state.settings.customRules.firstIndex(where: { $0.id == id }) { f(&state.settings.customRules[i]) }
    }

    private func actionTitle(_ a: String) -> String { a == "vpn" ? L("через VPN") : a == "direct" ? L("напрямую") : L("блок") }

    private func pickApp() {
        let p = NSOpenPanel()
        p.allowedContentTypes = [.application]
        p.directoryURL = URL(fileURLWithPath: "/Applications")
        guard p.runModal() == .OK, let u = p.url else { return }
        let exe = Bundle(url: u)?.executableURL?.lastPathComponent ?? u.deletingPathExtension().lastPathComponent
        state.settings.appRules.append(AppRule(process: exe, action: "vpn"))
    }
}

struct RuleSheet: View {
    @EnvironmentObject var state: AppState
    @Environment(\.dismiss) private var dismiss
    @State var rule: CustomRule

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text(L("Правило")).font(.headline)
            TextField(L("Название"), text: $rule.name)
            Picker(L("Действие"), selection: $rule.action) {
                Text(L("через VPN")).tag("vpn"); Text(L("напрямую")).tag("direct"); Text(L("блок")).tag("block")
            }
            Text(L("Сайты — по одному в строке (поддомены тоже)")).font(.caption).foregroundStyle(Slm.text2)
            LinesEditor(lines: $rule.domains, placeholder: "example.com")
            Text(L("IP и сети — по одному в строке (1.2.3.4 или 1.2.3.0/24)")).font(.caption).foregroundStyle(Slm.text2)
            LinesEditor(lines: $rule.ips, placeholder: "1.2.3.0/24", height: 70)
            HStack {
                Spacer()
                Button(L("Отмена")) { dismiss() }
                Button(L("Сохранить")) {
                    if let i = state.settings.customRules.firstIndex(where: { $0.id == rule.id }) { state.settings.customRules[i] = rule }
                    else { state.settings.customRules.append(rule) }
                    dismiss()
                }.keyboardShortcut(.defaultAction)
            }
        }
        .padding(22).frame(width: 520)
    }
}

// MARK: ИИ, игры и звонки

struct ServicesView: View {
    @EnvironmentObject var state: AppState
    @State private var editing: OwnService?

    private func toggle(_ id: String) -> Binding<Bool> {
        Binding(get: { !state.settings.disabledServices.contains(id) }, set: { on in
            if on { state.settings.disabledServices.removeAll { $0 == id } } else { state.settings.disabledServices.append(id) }
        })
    }

    var body: some View {
        Page(title: L("ИИ, игры и звонки"), subtitle: L("Свой переключатель у каждого сервиса. Программы различаются только в режиме TUN.")) {
            Card(title: L("ИИ")) {
                Toggle(L("ИИ через VPN при любом пресете"), isOn: $state.settings.aiViaVpn).bold()
                ownList("ai")
                LazyVGrid(columns: [GridItem(.flexible()), GridItem(.flexible())], alignment: .leading) {
                    ForEach(Catalog.inGroup(.ai)) { d in
                        Toggle(isOn: toggle(d.id)) {
                            VStack(alignment: .leading) { Text(L(d.name)); if !d.note.isEmpty { Text(L(d.note)).font(.caption).foregroundStyle(Slm.text2) } }
                        }
                    }
                }
            }
            Card(title: L("Игры")) {
                Toggle(L("Игровой режим (TUN)"), isOn: $state.settings.gameMode).bold()
                Toggle(L("Игровой UDP через VPN (матчмейкинг, сама игра), загрузки напрямую"), isOn: $state.settings.gamesViaVpn)
                    .disabled(!state.settings.gameMode)
                ownList("game")
                LazyVGrid(columns: [GridItem(.flexible()), GridItem(.flexible())], alignment: .leading) {
                    ForEach(MacRules.games) { g in Toggle(L(g.name), isOn: toggle(g.id)) }
                }
            }
            Card(title: L("Звонки и мессенджеры")) {
                Toggle(L("Звонки через VPN"), isOn: $state.settings.callsViaVpn).bold()
                ownList("call")
                ForEach(Catalog.inGroup(.call)) { d in Toggle(d.name, isOn: toggle(d.id)) }
            }
            Button(L("Добавить своё…")) { editing = OwnService() }
        }
        .sheet(item: $editing) { s in OwnServiceSheet(item: s) }
    }

    @ViewBuilder private func ownList(_ group: String) -> some View {
        ForEach(state.settings.ownServices.filter { $0.group == group }) { s in
            HStack {
                Toggle(isOn: Binding(get: { s.enabled }, set: { on in
                    if let i = state.settings.ownServices.firstIndex(where: { $0.id == s.id }) { state.settings.ownServices[i].enabled = on }
                })) { Text(s.name + "  ·  " + L("своё")) }
                Spacer()
                Button(L("Изменить")) { editing = s }
                Button(role: .destructive) { state.settings.ownServices.removeAll { $0.id == s.id } } label: { Image(systemName: "trash") }
            }
        }
    }
}

struct OwnServiceSheet: View {
    @EnvironmentObject var state: AppState
    @Environment(\.dismiss) private var dismiss
    @State var item: OwnService

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text(L("Своё правило")).font(.headline)
            TextField(L("Название"), text: $item.name)
            Picker(L("Список"), selection: $item.group) {
                Text(L("ИИ — всегда через VPN")).tag("ai")
                Text(L("Игры — как в игровом режиме")).tag("game")
                Text(L("Звонки — UDP через VPN")).tag("call")
            }
            Text(L("Сайты — по одному в строке (поддомены тоже)")).font(.caption).foregroundStyle(Slm.text2)
            LinesEditor(lines: $item.domains, placeholder: "example.com", height: 80)
            Text(L("IP и сети — по одному в строке (1.2.3.4 или 1.2.3.0/24)")).font(.caption).foregroundStyle(Slm.text2)
            LinesEditor(lines: $item.ips, placeholder: "1.2.3.0/24", height: 60)
            Text(L("Программы — имя процесса, по одному в строке")).font(.caption).foregroundStyle(Slm.text2)
            LinesEditor(lines: $item.processes, placeholder: "Telegram", height: 60)
            HStack {
                Spacer()
                Button(L("Отмена")) { dismiss() }
                Button(L("Сохранить")) {
                    if item.name.isEmpty { item.name = (item.domains + item.processes + item.ips).first ?? L("Своё") }
                    if let i = state.settings.ownServices.firstIndex(where: { $0.id == item.id }) { state.settings.ownServices[i] = item }
                    else { state.settings.ownServices.append(item) }
                    dismiss()
                }.keyboardShortcut(.defaultAction)
            }
        }
        .padding(22).frame(width: 540)
    }
}

// MARK: Kill switch

struct KillSwitchView: View {
    @EnvironmentObject var state: AppState

    var body: some View {
        Page(title: "Kill switch", subtitle: L("Если VPN отключился сам (сервер пропал, ядро упало, программу закрыли аварийно), трафик не уходит в интернет напрямую. Работает на файрволе pf, поэтому держится, даже когда SLMtune не запущен.")) {
            if !state.helperInstalled {
                Card(title: L("Нужен помощник")) {
                    Text(L("Правила файрвола ставит помощник с правами администратора.")).foregroundStyle(Slm.text2)
                    Button(L("Установить помощник")) { Task { await state.installHelper() } }
                }
            }
            Card {
                Toggle(L("Включить kill switch"), isOn: $state.settings.killSwitch).bold()
                Picker("", selection: $state.settings.killSwitchScope) {
                    Text(L("Весь трафик: без VPN интернет закрыт для всех программ")).tag("all")
                    Text(L("Только выбранные сайты и IP: остальное работает как обычно")).tag("selected")
                }
                .pickerStyle(.radioGroup).labelsHidden().disabled(!state.settings.killSwitch)
                Toggle(L("Локальная сеть (роутер, принтеры, AirPlay) без VPN"), isOn: $state.settings.excludeLocalNetworks)
                    .disabled(!state.settings.killSwitch || state.settings.killSwitchScope != "all")
                Toggle(L("Не открывать интернет и после ручного «Отключить» или выхода"), isOn: $state.settings.killSwitchStrict)
                    .disabled(!state.settings.killSwitch)
            }
            if state.settings.killSwitchScope == "selected" {
                Card(title: L("Сайты, IP и сети — по одному в строке"), note: L("Домены переводятся в IP при каждом подключении. У больших сайтов адреса меняются — для них надёжнее режим «весь трафик».")) {
                    LinesEditor(lines: $state.settings.killSwitchSites, placeholder: "example.com\n1.2.3.0/24")
                }
            }
            Card(title: L("Сейчас")) {
                Text(state.killSwitchActive == "off" ? L("Блокировки нет.") : state.killSwitchActive == "all" ? L("Действует: весь трафик без VPN закрыт.") : L("Действует: выбранное без VPN закрыто."))
                    .foregroundStyle(state.killSwitchActive == "off" ? Slm.text2 : Slm.warn)
                Button(L("Снять блокировку сейчас")) { Task { await state.setKillSwitch(off: true) } }
                    .disabled(state.killSwitchActive == "off")
            }
        }
    }
}

// MARK: Каскад

struct CascadeView: View {
    @EnvironmentObject var state: AppState

    var body: some View {
        Page(title: L("Каскад"), subtitle: L("Подключение к серверу через другой сервер. Последний в цепочке видит только адрес предыдущего, провайдер — только первый.")) {
            Card(title: L("Входной сервер для всех")) {
                Picker("", selection: $state.settings.cascadeEntryId) {
                    Text(L("Нет — каждый сервер сам по себе")).tag("")
                    ForEach(state.settings.servers) { s in Text("\(s.title) · \(ShareLinks.describe(s))").tag(s.id) }
                }.labelsHidden()
                Text(L("Первым может быть сервер на любом протоколе, в том числе TrustTunnel, AmneziaWG, WARP или Tor.")).font(.caption).foregroundStyle(Slm.text2)
            }
            Card(title: L("По серверам")) {
                ForEach(state.settings.servers.filter { $0.kind != "group" }) { s in
                    HStack {
                        VStack(alignment: .leading) {
                            Text(s.title)
                            Text(path(s)).font(.caption).foregroundStyle(Outbounds.hops(state.settings, s).isEmpty ? Slm.text2 : Slm.accent2)
                        }
                        Spacer()
                        Picker("", selection: Binding(get: { s.viaId }, set: { v in var x = s; x.viaId = v; state.update(x) })) {
                            Text(L("Напрямую (или через входной)")).tag("")
                            ForEach(state.settings.servers.filter { $0.id != s.id }) { r in Text(L("через ") + r.title).tag(r.id) }
                        }.labelsHidden().frame(width: 260)
                    }
                    Divider()
                }
            }
        }
    }

    private func path(_ s: Server) -> String {
        let hops = Outbounds.hops(state.settings, s)
        if hops.isEmpty { return L("Напрямую") }
        return ([L("Вы")] + hops.map(\.title) + [s.title, L("интернет")]).joined(separator: " → ")
    }
}

// MARK: Zapret

struct ZapretView: View {
    @EnvironmentObject var state: AppState
    private let quick: [(String, [String])] = [
        ("YouTube", ["youtube.com", "googlevideo.com", "ytimg.com", "youtu.be", "ggpht.com"]),
        ("Discord", ["discord.com", "discord.gg", "discordapp.com", "discordapp.net", "discord.media"]),
        ("Instagram", ["instagram.com", "cdninstagram.com"]),
        ("X / Twitter", ["x.com", "twitter.com", "twimg.com"]),
        ("Facebook", ["facebook.com", "fbcdn.net"]),
        ("Twitch", ["twitch.tv", "ttvnw.net"]),
        ("Rutracker", ["rutracker.org"]),
        ("LinkedIn", ["linkedin.com", "licdn.com"]),
    ]

    var body: some View {
        Page(title: "Zapret", subtitle: L("Обход DPI без VPN (bol-van/zapret, tpws): выбранные сайты идут напрямую, но так, что провайдер не может их распознать и заблокировать.")) {
            Card {
                Toggle(L("Zapret вместе с VPN: выбранные сайты — через tpws, а не через сервер"), isOn: $state.settings.zapretOn)
                HStack {
                    Button(state.status == .on ? L("Работает подключение") : L("Только Zapret, без VPN")) { state.connect(zapretOnly: true) }
                        .disabled(state.status != .off)
                    Text(L("Без сервера: всё напрямую, выбранные сайты через tpws.")).font(.caption).foregroundStyle(Slm.text2)
                }
            }
            Card(title: L("Стратегия"), note: L("Провайдеры режут по-разному: если сайты не открываются, попробуйте другую.")) {
                Picker("", selection: $state.settings.zapretStrategy) {
                    ForEach(Zapret.strategies, id: \.id) { s in Text(L(s.title)).tag(s.id) }
                }.pickerStyle(.radioGroup).labelsHidden()
            }
            Card(title: L("Сайты")) {
                LinesEditor(lines: $state.settings.zapretSites, placeholder: "youtube.com", height: 150)
                Text(L("Быстро добавить:")).font(.caption).foregroundStyle(Slm.text2)
                HStack {
                    ForEach(quick, id: \.0) { q in
                        Button("+ " + q.0) {
                            for d in q.1 where !state.settings.zapretSites.contains(d) { state.settings.zapretSites.append(d) }
                        }
                    }
                }
            }
        }
    }
}

// MARK: Подписки

struct SubscriptionsView: View {
    @EnvironmentObject var state: AppState
    @State private var url = ""

    var body: some View {
        Page(title: L("Подписки"), subtitle: L("Списки серверов от провайдера. Обновляются сами; остаток трафика и срок — из заголовка провайдера.")) {
            Card {
                HStack {
                    TextField("https://…", text: $url)
                    Button(L("Добавить")) {
                        let u = url
                        url = ""
                        Task { await state.addSubscription(url: u) }
                    }.disabled(!(url.hasPrefix("https://") || url.hasPrefix("http://")))
                    Button(L("Обновить все")) { Task { await state.refreshAll(includeManual: true) } }
                }
            }
            ForEach(state.settings.subscriptions) { sub in
                Card {
                    HStack {
                        VStack(alignment: .leading, spacing: 4) {
                            Text(sub.name).font(.headline)
                            Text(L("серверов: %d", sub.count) + (sub.lastUpdate.map { " · " + $0.formatted(date: .abbreviated, time: .shortened) } ?? ""))
                                .font(.caption).foregroundStyle(Slm.text2)
                            let info = Subscriptions.describe(sub)
                            if !info.isEmpty { Text(info).font(.callout) }
                            if sub.total > 0 {
                                ProgressView(value: Double(min(sub.upload + sub.download, sub.total)), total: Double(sub.total)).tint(Slm.accent)
                            }
                            if let e = sub.lastError { Text(e).font(.caption).foregroundStyle(Slm.err) }
                        }
                        Spacer()
                        Toggle(L("Авто"), isOn: Binding(get: { sub.autoUpdate }, set: { v in
                            if let i = state.settings.subscriptions.firstIndex(where: { $0.id == sub.id }) { state.settings.subscriptions[i].autoUpdate = v }
                        }))
                        Button(L("Обновить")) { Task { var s = sub; await state.refresh(&s) } }
                        Button(role: .destructive) {
                            state.settings.subscriptions.removeAll { $0.id == sub.id }
                            state.remove(Set(state.settings.servers.filter { $0.subscriptionId == sub.id }.map(\.id)))
                        } label: { Image(systemName: "trash") }
                    }
                }
            }
        }
    }
}
