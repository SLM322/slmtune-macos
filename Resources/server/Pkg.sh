pkg() {
  if command -v apt-get >/dev/null 2>&1; then DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "$@" >/dev/null 2>&1 || { apt-get update -qq >/dev/null 2>&1; DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "$@" >/dev/null; }
  elif command -v dnf >/dev/null 2>&1; then dnf install -y -q "$@" >/dev/null
  elif command -v yum >/dev/null 2>&1; then yum install -y -q "$@" >/dev/null
  else echo "[slm] no apt/dnf/yum: install $* by hand"; return 1; fi
}

