#!/usr/bin/env sh
# Installs build prerequisites and the official Rust toolchain only after --apply.
set -eu

apply=0
install_ssh=0
for arg in "$@"; do
  case "$arg" in --apply) apply=1 ;; --install-ssh) install_ssh=1 ;; -h|--help) echo "Usage: $0 [--apply] [--install-ssh]"; exit 0 ;; *) echo "Unknown option: $arg" >&2; exit 2 ;; esac
done
arch=$(uname -m)
case "$arch" in x86_64|aarch64) ;; *) echo "Unsupported architecture: $arch" >&2; exit 1 ;; esac
. /etc/os-release 2>/dev/null || true
echo "OpenGate Linux bootstrap: ${PRETTY_NAME:-unknown Linux} ($arch)"
echo "Changes on --apply: install compiler/build prerequisites and Rust via https://rustup.rs."
if [ "$install_ssh" -eq 1 ]; then echo "Also requested: install an OpenSSH client package."; else echo "OpenSSH will not be installed."; fi
[ "$apply" -eq 1 ] || { echo "Dry run only. Re-run with --apply to make these changes."; exit 0; }
if command -v apt-get >/dev/null 2>&1; then
  sudo apt-get update
  sudo apt-get install -y build-essential pkg-config libssl-dev curl ca-certificates git ${install_ssh:+openssh-client}
elif command -v dnf >/dev/null 2>&1; then
  sudo dnf install -y gcc gcc-c++ make pkgconf-pkg-config openssl-devel curl ca-certificates git ${install_ssh:+openssh-clients}
elif command -v pacman >/dev/null 2>&1; then
  sudo pacman -Sy --needed --noconfirm base-devel pkgconf openssl curl ca-certificates git ${install_ssh:+openssh}
else
  echo "No supported package manager found; install a C compiler, pkg-config, OpenSSL headers, curl and git yourself." >&2; exit 1
fi
tmp=$(mktemp)
trap 'rm -f "$tmp"' EXIT
curl --proto '=https' --tlsv1.2 -fsS https://sh.rustup.rs -o "$tmp"
sh "$tmp" -y --profile minimal
echo "Rust installed. Open a new shell, then run: cargo build --release"
