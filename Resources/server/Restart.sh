set +e
if systemctl list-unit-files sing-box.service >/dev/null 2>&1; then systemctl restart sing-box; fi
if [ -f /opt/trusttunnel/slm-managed ]; then systemctl restart trusttunnel; fi
sleep 2
echo "singbox_active=$(systemctl is-active sing-box 2>/dev/null)"
echo "tt_active=$(systemctl is-active trusttunnel 2>/dev/null)"
echo "restart=ok"
