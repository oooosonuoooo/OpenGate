#!/usr/bin/env bash
set -euo pipefail

MODE="host"
PORT="44344"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --mode) MODE="${2:-}"; shift 2 ;;
    --port) PORT="${2:-}"; shift 2 ;;
    *) echo "Unknown option: $1" >&2; exit 2 ;;
  esac
done

case "$MODE" in host|controller|both) ;; *) echo "--mode must be host, controller, or both" >&2; exit 2;; esac

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SOURCE="$SCRIPT_DIR/../opengate.py"

SUDO=""
if [[ $EUID -ne 0 ]]; then SUDO="sudo"; fi

install_python() {
  command -v python3 >/dev/null 2>&1 && return 0
  echo "Python 3 not found; installing it..."
  if command -v apt-get >/dev/null 2>&1; then $SUDO apt-get update && $SUDO apt-get install -y python3
  elif command -v dnf >/dev/null 2>&1; then $SUDO dnf install -y python3
  elif command -v yum >/dev/null 2>&1; then $SUDO yum install -y python3
  elif command -v pacman >/dev/null 2>&1; then $SUDO pacman -Sy --noconfirm python
  elif command -v zypper >/dev/null 2>&1; then $SUDO zypper --non-interactive install python3
  else echo "No supported package manager found. Install Python 3.10+ manually." >&2; exit 1; fi
}

install_ssh_server() {
  if command -v sshd >/dev/null 2>&1; then return 0; fi
  echo "OpenSSH Server not found; installing it..."
  if command -v apt-get >/dev/null 2>&1; then $SUDO apt-get update && $SUDO apt-get install -y openssh-server
  elif command -v dnf >/dev/null 2>&1; then $SUDO dnf install -y openssh-server
  elif command -v yum >/dev/null 2>&1; then $SUDO yum install -y openssh-server
  elif command -v pacman >/dev/null 2>&1; then $SUDO pacman -Sy --noconfirm openssh
  elif command -v zypper >/dev/null 2>&1; then $SUDO zypper --non-interactive install openssh
  else echo "No supported package manager found. Install OpenSSH Server manually." >&2; exit 1; fi
}

install_ssh_client() {
  command -v ssh >/dev/null 2>&1 && return 0
  echo "OpenSSH Client not found; installing it..."
  if command -v apt-get >/dev/null 2>&1; then $SUDO apt-get update && $SUDO apt-get install -y openssh-client
  elif command -v dnf >/dev/null 2>&1; then $SUDO dnf install -y openssh-clients
  elif command -v yum >/dev/null 2>&1; then $SUDO yum install -y openssh-clients
  elif command -v pacman >/dev/null 2>&1; then $SUDO pacman -Sy --noconfirm openssh
  elif command -v zypper >/dev/null 2>&1; then $SUDO zypper --non-interactive install openssh-clients
  fi
}

install_python

if [[ "$MODE" == "host" || "$MODE" == "both" ]]; then
  if [[ $EUID -ne 0 ]]; then
    echo "Host installation needs root. Re-running with sudo..."
    exec sudo "$0" --mode "$MODE" --port "$PORT"
  fi
  install_ssh_server
  install -d -m 755 /opt/opengate
  install -m 755 "$SOURCE" /opt/opengate/opengate.py
  cat >/usr/local/bin/opengate <<'EOF'
#!/bin/sh
exec /usr/bin/env python3 /opt/opengate/opengate.py "$@"
EOF
  chmod 755 /usr/local/bin/opengate

  if systemctl list-unit-files 2>/dev/null | grep -q '^ssh\.service'; then
    systemctl enable --now ssh
  elif systemctl list-unit-files 2>/dev/null | grep -q '^sshd\.service'; then
    systemctl enable --now sshd
  fi

  cat >/etc/systemd/system/opengate-host.service <<EOF
[Unit]
Description=OpenGate SSH transport host
After=network-online.target ssh.service sshd.service
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/opengate host --system --bind 0.0.0.0:${PORT}
Restart=always
RestartSec=3
UMask=0077

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable --now opengate-host.service

  if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q '^Status: active'; then
    ufw allow "${PORT}/tcp" >/dev/null || true
  fi
  if command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
    firewall-cmd --permanent --add-port="${PORT}/tcp" >/dev/null || true
    firewall-cmd --reload >/dev/null || true
  fi
fi

if [[ "$MODE" == "controller" ]]; then
  install_ssh_client
  mkdir -p "$HOME/.local/bin"
  install -m 755 "$SOURCE" "$HOME/.local/bin/opengate"
  echo "Controller installed at $HOME/.local/bin/opengate"
elif [[ "$MODE" == "both" ]]; then
  install_ssh_client
fi

echo
echo "OpenGate installation complete."
if [[ "$MODE" == "host" || "$MODE" == "both" ]]; then
  echo "Host is configured to start automatically after reboot."
  echo "Generate a 15-minute single-use pairing token with:"
  echo "  sudo opengate token --system --advertise <reachable-ip-or-dns>:${PORT}"
fi
if [[ "$MODE" == "controller" || "$MODE" == "both" ]]; then
  echo "Pair/connect with:"
  echo "  opengate connect --token '<TOKEN>'"
fi
