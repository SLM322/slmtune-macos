set -e
if [ ! -x /opt/trusttunnel/trusttunnel_endpoint ]; then
  echo "[slm] installing TrustTunnel"
  if ! command -v curl >/dev/null 2>&1; then
    if command -v apt-get >/dev/null 2>&1; then apt-get update -qq && apt-get install -y -qq curl ca-certificates
    elif command -v dnf >/dev/null 2>&1; then dnf install -y -q curl
    fi
  fi
  curl -fsSL https://raw.githubusercontent.com/TrustTunnel/TrustTunnel/refs/heads/master/scripts/install.sh | sh -s -
fi
cd /opt/trusttunnel
mkdir -p certs
echo '{{B64(certPem)}}' | base64 -d > certs/slm-cert.pem
echo '{{B64(keyPem)}}' | base64 -d > certs/slm-key.pem
echo '{{B64(vpnToml)}}' | base64 -d > vpn.toml
echo '{{B64(hostsToml)}}' | base64 -d > hosts.toml
echo '{{B64(credentialsToml)}}' | base64 -d > credentials.toml
chmod 600 certs/slm-key.pem credentials.toml
touch slm-managed
if [ ! -f /etc/systemd/system/trusttunnel.service ]; then
  cp trusttunnel.service.template /etc/systemd/system/trusttunnel.service
  systemctl daemon-reload
fi
systemctl enable trusttunnel >/dev/null 2>&1 || true
systemctl restart trusttunnel
sleep 2
echo "tt_active=$(systemctl is-active trusttunnel || true)"
echo "tt=ok"
