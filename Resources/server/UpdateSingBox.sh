set -e
OLD=$(sing-box version 2>/dev/null | head -1 | awk '{print $3}')
echo "[slm] sing-box now: ${OLD:-none}"
curl -fsSL https://sing-box.app/install.sh | sh
NEW=$(sing-box version | head -1 | awk '{print $3}')
if [ -f /etc/sing-box/config.json ]; then
  sing-box check -c /etc/sing-box/config.json
  systemctl restart sing-box
fi
echo "singbox=$NEW"
echo "update=ok"
