set -e
if [ "$(swapon --show --noheadings | wc -l)" = 0 ]; then
  fallocate -l 1G /swapfile-slm 2>/dev/null || dd if=/dev/zero of=/swapfile-slm bs=1M count=1024 status=none
  chmod 600 /swapfile-slm
  mkswap /swapfile-slm >/dev/null
  swapon /swapfile-slm
  grep -q swapfile-slm /etc/fstab || echo '/swapfile-slm none swap sw 0 0' >> /etc/fstab
  echo "[slm] swap 1G on"
else
  echo "[slm] swap already there: $(swapon --show --noheadings | awk '{print $1" "$3}' | tr '\n' ' ')"
fi
if command -v timedatectl >/dev/null 2>&1; then timedatectl set-ntp true 2>/dev/null || true; fi
echo "[slm] time: $(date -u '+%Y-%m-%d %H:%M:%S UTC'), synced: $(timedatectl show -p NTPSynchronized --value 2>/dev/null || echo '?')"
echo "tools=ok"
