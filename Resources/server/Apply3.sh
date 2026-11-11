echo '{{B64(metaJson)}}' | base64 -d > slm-meta.json
chmod 600 slm-meta.json
UFW=""; FWD=""
if command -v ufw >/dev/null 2>&1; then UFW=$(ufw status 2>/dev/null | head -1 | awk '{print $2}' || true); fi
if command -v firewall-cmd >/dev/null 2>&1; then FWD=$(firewall-cmd --state 2>/dev/null || true); fi
openp() { if [ "$UFW" = active ]; then ufw allow "$1" >/dev/null; fi; if [ "$FWD" = running ]; then firewall-cmd -q --permanent --add-port="$1"; fi; echo "[slm] port $1 open"; }
closep() { if [ "$UFW" = active ]; then ufw delete allow "$1" >/dev/null 2>&1 || true; fi; if [ "$FWD" = running ]; then firewall-cmd -q --permanent --remove-port="$1" || true; fi; echo "[slm] port $1 closed"; }

