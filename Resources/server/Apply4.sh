if [ "$(sysctl -n net.ipv4.tcp_congestion_control)" != bbr ]; then
  printf 'net.core.default_qdisc=fq\nnet.ipv4.tcp_congestion_control=bbr\n' > /etc/sysctl.d/99-slm-bbr.conf
  sysctl -q --system >/dev/null 2>&1 || true
fi
echo "cc=$(sysctl -n net.ipv4.tcp_congestion_control)"

