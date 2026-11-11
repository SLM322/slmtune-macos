acct() {
  if ! command -v nft >/dev/null 2>&1 || ! command -v python3 >/dev/null 2>&1; then
    if command -v apt-get >/dev/null 2>&1; then apt-get install -y -qq nftables python3 >/dev/null 2>&1
    elif command -v dnf >/dev/null 2>&1; then dnf install -y -q nftables python3 >/dev/null 2>&1
    elif command -v yum >/dev/null 2>&1; then yum install -y -q nftables python3 >/dev/null 2>&1
    fi
  fi
  command -v nft >/dev/null 2>&1 && command -v python3 >/dev/null 2>&1 || return 1
  echo '{{B64(UsageScript)}}' | base64 -d > /etc/sing-box/slm-usage.py || return 1
  echo '{{B64(nft)}}' | base64 -d > /etc/sing-box/slm.nft || return 1
  python3 /etc/sing-box/slm-usage.py >/dev/null 2>&1
  nft -f /etc/sing-box/slm.nft || return 1
  python3 /etc/sing-box/slm-usage.py reloaded || return 1
  echo '{{B64(AcctUnit)}}' | base64 -d > /etc/systemd/system/slm-acct.service
  echo '{{B64(UsageUnit)}}' | base64 -d > /etc/systemd/system/slm-usage.service
  echo '{{B64(UsageTimer)}}' | base64 -d > /etc/systemd/system/slm-usage.timer
  systemctl daemon-reload
  systemctl enable slm-acct.service >/dev/null 2>&1
  systemctl enable --now slm-usage.timer >/dev/null 2>&1
  return 0
}
if acct; then echo "acct=on"; else echo "[slm] traffic accounting is not available on this server (needs nftables and python3)"; fi

