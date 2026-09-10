#!/usr/bin/env sh
# Installs an already-built OpenGate binary. It never deletes state on uninstall.
set -eu
bin=target/release/opengate
system=0
full_admin=0
for arg in "$@"; do
  case "$arg" in --bin=*) bin=${arg#*=} ;; --system) system=1 ;; --full-admin) full_admin=1 ;; -h|--help) echo "Usage: $0 [--bin=PATH] [--system] [--full-admin]"; exit 0 ;; *) echo "Unknown option: $arg" >&2; exit 2 ;; esac
done
[ -x "$bin" ] || { echo "Expected executable binary at $bin" >&2; exit 1; }
if [ "$system" -eq 1 ]; then
  [ "$(id -u)" -eq 0 ] || { echo "System installation requires root." >&2; exit 1; }
  install -Dm755 "$bin" /usr/local/bin/opengate
  data=/var/lib/opengate
  if [ "$full_admin" -eq 1 ]; then
    [ -f "$data/config.toml" ] || { echo "Full Admin needs an existing $data/config.toml with allow_admin = true; install the standard service first, configure it as owner, then retry." >&2; exit 1; }
    grep -Eq '^[[:space:]]*allow_admin[[:space:]]*=[[:space:]]*true[[:space:]]*(#.*)?$' "$data/config.toml" || { echo "Full Admin requires the owner-approved setting allow_admin = true in $data/config.toml." >&2; exit 1; }
    set -- --full-admin
  else
    set --
  fi
  exec /usr/local/bin/opengate --data-dir "$data" service install --system "$@"
fi
install -d "$HOME/.local/bin"
install -m755 "$bin" "$HOME/.local/bin/opengate"
exec "$HOME/.local/bin/opengate" --data-dir "$HOME/.local/share/opengate" service install
