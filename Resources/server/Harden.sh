set -e
pkg fail2ban || true
if command -v fail2ban-client >/dev/null 2>&1; then
  mkdir -p /etc/fail2ban/jail.d
  printf '[sshd]\nenabled = true\nmaxretry = 5\nfindtime = 10m\nbantime = 1h\n' > /etc/fail2ban/jail.d/slm-sshd.conf
  systemctl enable fail2ban >/dev/null 2>&1 || true
  systemctl restart fail2ban
  echo "[slm] fail2ban: sshd jail on (5 tries, ban 1h)"
fi
U="${SUDO_USER:-root}"
H=$(getent passwd "$U" | cut -d: -f6)
if grep -q ' slmtune$' "$H/.ssh/authorized_keys" 2>/dev/null; then
  mkdir -p /etc/ssh/sshd_config.d
  printf 'PasswordAuthentication no\nKbdInteractiveAuthentication no\nPermitRootLogin prohibit-password\n' > /etc/ssh/sshd_config.d/00-slm.conf
  if sshd -t 2>/dev/null; then systemctl reload ssh 2>/dev/null || systemctl reload sshd; echo "[slm] password logins off: key only"
  else rm -f /etc/ssh/sshd_config.d/00-slm.conf; echo "[slm] sshd config check failed, passwords left on"; fi
else
  echo "[slm] the app's key is not on the server: password logins left on"
fi
echo "harden=ok"
