set -e
if command -v apt-get >/dev/null 2>&1; then
  pkg unattended-upgrades
  printf 'APT::Periodic::Update-Package-Lists "1";\nAPT::Periodic::Unattended-Upgrade "1";\n' > /etc/apt/apt.conf.d/20auto-upgrades
  echo "[slm] unattended-upgrades on (security updates daily)"
elif command -v dnf >/dev/null 2>&1; then
  pkg dnf-automatic
  sed -i 's/^apply_updates.*/apply_updates = yes/; s/^upgrade_type.*/upgrade_type = security/' /etc/dnf/automatic.conf
  systemctl enable --now dnf-automatic.timer >/dev/null
  echo "[slm] dnf-automatic on (security updates)"
fi
echo "tools=ok"
