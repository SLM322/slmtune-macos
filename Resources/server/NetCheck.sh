set +e
echo "[slm] ip: $(curl -4 -s --max-time 8 https://api.ipify.org) $(curl -s --max-time 8 https://ipinfo.io/country)"
S=$(curl -s -o /dev/null --max-time 20 -w '%{speed_download}' 'https://speed.cloudflare.com/__down?bytes=50000000')
echo "[slm] download from Cloudflare: $(awk -v s="${S:-0}" 'BEGIN{printf "%.0f Mbit/s", s*8/1000000}')"
chk() { c=$(curl -s -o /dev/null --max-time 10 -w '%{http_code}' "$2"); echo "[slm] $1: HTTP ${c:-000}"; }
chk "ChatGPT" https://chatgpt.com/
chk "OpenAI API" https://api.openai.com/v1/models
chk "Claude" https://claude.ai/
chk "Gemini" https://gemini.google.com/
chk "YouTube" https://www.youtube.com/
chk "Netflix" https://www.netflix.com/title/80018499
chk "Steam" https://store.steampowered.com/
if curl -s --max-time 10 https://chatgpt.com/cdn-cgi/trace | grep -q 'loc='; then echo "[slm] OpenAI sees: $(curl -s --max-time 10 https://chatgpt.com/cdn-cgi/trace | grep loc=)"; fi
echo "[slm] 403 or 451 means the site blocks this server's country or hosting"
echo "tools=ok"
