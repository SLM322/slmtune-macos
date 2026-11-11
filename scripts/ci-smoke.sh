#!/usr/bin/env bash
# Real checks on a macOS machine (GitHub Actions), after scripts/build-app.sh:
#  1. every bundled core starts and prints its version;
#  2. sing-box accepts every config the app generates (tools/ConfigDump);
#  3. Zapret without VPN, proxy mode: tpws + sing-box as user processes, curl through the local proxy;
#  4. the root helper, installed the way the app installs it: TUN through the helper, the pf kill switch.
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
APP="$ROOT/dist/SLMtune.app"
CORES="$APP/Contents/Resources/cores"
SB="$CORES/sing-box"
FAIL=0
ok() { echo "PASS  $*"; }
bad() { echo "FAIL  $*"; FAIL=1; }

echo "== 1. cores"
for c in sing-box:version xray:version mihomo:-v hysteria:version naive:--version trusttunnel_client:--version tor/tor:--version tpws:--version; do
  bin="${c%%:*}"; arg="${c#*:}"
  out="$("$CORES/$bin" $arg 2>&1 | head -2 | tr '\n' ' ')"
  if [ -x "$CORES/$bin" ] && [ -n "$out" ]; then ok "$bin: ${out:0:90}"; else bad "$bin does not run: $out"; fi
  lipo -archs "$CORES/$bin" 2>/dev/null | grep -q "x86_64 arm64\|arm64 x86_64" && ok "$bin is universal" || echo "note: $bin is $(lipo -archs "$CORES/$bin" 2>/dev/null)"
done

echo "== 2. generated configs"
CFG="$(mktemp -d)"
(cd "$ROOT" && SLM_MIXED_PORT=17890 SLM_ZAPRET_PORT=17891 swift run -c release ConfigDump "$CFG" >/dev/null)
for f in "$CFG"/singbox-*.json; do
  if "$SB" check -c "$f" >/dev/null 2>"$CFG/err"; then ok "sing-box check $(basename "$f")"; else bad "sing-box check $(basename "$f"): $(head -c 300 "$CFG/err")"; fi
done
"$CORES/xray" run -test -c "$CFG/xray.json" >/dev/null 2>&1 && ok "xray -test" || bad "xray -test"

echo "== 3. Zapret without VPN (proxy mode)"
"$CORES/tpws" --socks --bind-addr=127.0.0.1 --port=17891 --split-pos=1,midsld >"$CFG/tpws.log" 2>&1 &
TP=$!
"$SB" run -c "$CFG/singbox-mac-zapret-only.json" -D "$CFG" >"$CFG/sb.log" 2>&1 &
SBP=$!
sleep 3
code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 20 -x socks5h://127.0.0.1:17890 https://example.com)"
[ "$code" = 200 ] && ok "example.com through sing-box → tpws: HTTP $code" || { bad "zapret proxy: HTTP $code"; tail -5 "$CFG/sb.log" "$CFG/tpws.log"; }
code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 20 -x http://127.0.0.1:17890 https://www.apple.com)"
[ "$code" = 200 ] && ok "apple.com direct through the HTTP proxy: HTTP $code" || bad "direct via http proxy: HTTP $code"
kill $SBP 2>/dev/null

echo "== 4. helper (TUN, kill switch)"
H=/Library/PrivilegedHelperTools/com.slmtune.helper
D="/Library/Application Support/SLMtune"
sudo mkdir -p "$D/bin" "$D/run" /Library/PrivilegedHelperTools
sudo install -m 755 -o root -g wheel "$APP/Contents/Resources/helper/SLMtuneHelper" "$H"
sudo install -m 755 -o root -g wheel "$SB" "$D/bin/sing-box"
echo "$(id -u)" | sudo tee "$D/owner" >/dev/null
cat > "$CFG/helper.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict><key>Label</key><string>com.slmtune.helper</string>
<key>ProgramArguments</key><array><string>$H</string></array><key>RunAtLoad</key><true/><key>KeepAlive</key><true/>
<key>StandardOutPath</key><string>/var/log/com.slmtune.helper.log</string><key>StandardErrorPath</key><string>/var/log/com.slmtune.helper.log</string></dict></plist>
EOF
sudo install -m 644 -o root -g wheel "$CFG/helper.plist" /Library/LaunchDaemons/com.slmtune.helper.plist
sudo launchctl bootstrap system /Library/LaunchDaemons/com.slmtune.helper.plist
sleep 2
ask() { python3 - "$@" <<'PY'
import json, socket, sys
req = {"cmd": sys.argv[1]}
for kv in sys.argv[2:]:
    k, v = kv.split("=", 1)
    req[k] = open(v[1:]).read() if v.startswith("@") else json.loads(v)
s = socket.socket(socket.AF_UNIX); s.settimeout(60); s.connect("/var/run/com.slmtune.helper.sock")
s.sendall(json.dumps(req).encode() + b"\n")
print(s.makefile().readline().strip())
PY
}
r="$(ask ping)"; echo "$r" | grep -q '"ok":true' && ok "helper ping: $r" || bad "helper ping: $r"
r="$(ask start config=@"$CFG/singbox-mac-zapret-only-tun.json")"
if echo "$r" | grep -q '"ok":true'; then
  ok "TUN started through the helper"
  ifconfig | grep -q '^utun' && ok "utun interface is up" || bad "no utun interface"
  code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 20 https://example.com)"
  [ "$code" = 200 ] && ok "example.com through TUN → tpws: HTTP $code" || bad "TUN: HTTP $code"
  sudo tail -5 "$D/run/singbox.log"
  r="$(ask stop)"; echo "$r" | grep -q '"ok":true' && ok "TUN stopped" || bad "stop: $r"
else
  bad "TUN start: $r"; sudo tail -20 /var/log/com.slmtune.helper.log
fi
r="$(ask killswitch scope='"all"' servers='[]' allowLan=true)"
if echo "$r" | grep -q '"killSwitch":"all"'; then
  ok "kill switch on (pf)"
  code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 8 https://example.com)"
  [ "$code" = 000 ] && ok "internet shut while the kill switch is on" || bad "kill switch let through: HTTP $code"
  r="$(ask killswitch scope='"off"')"
  code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 20 https://example.com)"
  [ "$code" = 200 ] && ok "internet back after the kill switch is off" || bad "after kill switch off: HTTP $code"
else
  bad "kill switch: $r"
fi
r="$(ask proxy on=true port=17890)"; echo "$r" | grep -q '"ok":true' && ok "system proxy on" || bad "proxy: $r"
networksetup -getsecurewebproxy "$(networksetup -listallnetworkservices | sed -n 2p)" | grep -q 17890 && ok "system proxy points at 127.0.0.1:17890" || bad "system proxy not set"
ask proxy on=false >/dev/null
kill $TP 2>/dev/null
sudo launchctl bootout system/com.slmtune.helper 2>/dev/null
exit $FAIL
