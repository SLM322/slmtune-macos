set -e
export DEBIAN_FRONTEND=noninteractive
if ! command -v sing-box >/dev/null 2>&1; then
  echo "[slm] installing sing-box"
  if ! command -v curl >/dev/null 2>&1; then
    if command -v apt-get >/dev/null 2>&1; then apt-get update -qq && apt-get install -y -qq curl ca-certificates
    elif command -v dnf >/dev/null 2>&1; then dnf install -y -q curl
    elif command -v yum >/dev/null 2>&1; then yum install -y -q curl
    fi
  fi
  curl -fsSL https://sing-box.app/install.sh | sh
fi
echo "singbox=$(sing-box version | head -1 | awk '{print $3}')"
