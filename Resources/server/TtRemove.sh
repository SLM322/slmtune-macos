set -e
if [ -f /opt/trusttunnel/slm-managed ]; then
  systemctl disable --now trusttunnel >/dev/null 2>&1 || true
  rm -f /opt/trusttunnel/slm-managed
  echo "[slm] TrustTunnel stopped"
fi
echo "tt=ok"
