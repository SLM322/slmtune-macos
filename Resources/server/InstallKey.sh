set -e
U="${SUDO_USER:-root}"
H=$(getent passwd "$U" | cut -d: -f6)
mkdir -p "$H/.ssh"
chmod 700 "$H/.ssh"
touch "$H/.ssh/authorized_keys"
grep -qxF '{{publicKey}}' "$H/.ssh/authorized_keys" || echo '{{publicKey}}' >> "$H/.ssh/authorized_keys"
chmod 600 "$H/.ssh/authorized_keys"
chown -R "$U" "$H/.ssh"
echo "key=ok"
