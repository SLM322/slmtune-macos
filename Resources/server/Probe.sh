set +e
. /etc/os-release 2>/dev/null
echo "os=${PRETTY_NAME:-unknown}"
echo "arch=$(uname -m)"
if command -v sing-box >/dev/null 2>&1; then echo "singbox=$(sing-box version 2>/dev/null | head -1 | awk '{print $3}')"; fi
echo "singbox_active=$(systemctl is-active sing-box 2>/dev/null)"
echo "cc=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null)"
if command -v ufw >/dev/null 2>&1; then echo "ufw=$(ufw status 2>/dev/null | head -1 | awk '{print $2}')"; fi
if command -v firewall-cmd >/dev/null 2>&1; then echo "firewalld=$(firewall-cmd --state 2>/dev/null)"; fi
ss -Hltnup 2>/dev/null | awk '{print "listen=" $1 " " $5 " " $7}'
if [ -f /etc/sing-box/config.json ]; then echo "config=$(base64 -w0 /etc/sing-box/config.json)"; fi
if [ -f /etc/sing-box/slm-meta.json ]; then echo "meta=$(base64 -w0 /etc/sing-box/slm-meta.json)"; fi
if [ -f /etc/sing-box/slm-usage.py ]; then python3 /etc/sing-box/slm-usage.py >/dev/null 2>&1; fi
if [ -f /etc/sing-box/slm-usage.json ]; then echo "usage=$(base64 -w0 /etc/sing-box/slm-usage.json)"; fi
if nft list table inet slm >/dev/null 2>&1; then echo "acct=on"; fi
if [ -x /opt/trusttunnel/trusttunnel_endpoint ]; then echo "tt_installed=1"; fi
if [ -f /opt/trusttunnel/slm-managed ]; then echo "tt_managed=1"; fi
echo "tt_active=$(systemctl is-active trusttunnel 2>/dev/null)"
echo "load=$(cut -d' ' -f1 /proc/loadavg 2>/dev/null)"
echo "cpus=$(nproc 2>/dev/null)"
echo "mem=$(free -m 2>/dev/null | awk '/^Mem:/{print $3"/"$2}')"
echo "disk=$(df -P / 2>/dev/null | awk 'NR==2{print $3"/"$2}')"
echo "uptime=$(cut -d. -f1 /proc/uptime 2>/dev/null)"
echo "probe=ok"
