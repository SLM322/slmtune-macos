if [ -f config.json ]; then cp config.json "config.json.bak.$(date +%s)"; fi
ls -1t config.json.bak.* 2>/dev/null | tail -n +6 | xargs -r rm -f
echo '{{B64(configJson)}}' | base64 -d > config.json.new
sing-box check -c config.json.new
mv config.json.new config.json
chmod 600 config.json
systemctl enable sing-box >/dev/null 2>&1 || true
systemctl restart sing-box
sleep 1
echo "singbox_active=$(systemctl is-active sing-box || true)"

