#!/usr/bin/env bash
set -euo pipefail
DEVICE="${1:-}"
PORT="${2:-2222}"
if [[ -z "$DEVICE" ]]; then
  echo "Usage: $0 <saved-device-name> [local-port]" >&2
  exit 2
fi
if ! command -v opengate >/dev/null 2>&1; then
  echo "opengate is not in PATH. Install controller mode first." >&2
  exit 1
fi
mkdir -p "$HOME/.config/systemd/user"
OPENGATE_BIN="$(command -v opengate)"
cat >"$HOME/.config/systemd/user/opengate-controller.service" <<EOF
[Unit]
Description=OpenGate controller proxy for ${DEVICE}
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=${OPENGATE_BIN} connect --device ${DEVICE} --listen 127.0.0.1:${PORT} --retry-seconds 300
Restart=always
RestartSec=3

[Install]
WantedBy=default.target
EOF
systemctl --user daemon-reload
systemctl --user enable --now opengate-controller.service
if command -v loginctl >/dev/null 2>&1; then
  sudo loginctl enable-linger "$USER" >/dev/null 2>&1 || true
fi
echo "Controller auto-start enabled. Local SSH endpoint: 127.0.0.1:${PORT}"
