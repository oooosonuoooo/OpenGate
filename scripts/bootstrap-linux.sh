#!/usr/bin/env sh
# Developer prerequisites and build. System changes require explicit --apply.
set -eu
apply=0
install_ssh=0
for arg in "$@"; do
  case "$arg" in
    --apply) apply=1 ;;
    --install-ssh|--install-ssh-server) install_ssh=1 ;;
    -h|--help) echo "Usage: $0 [--apply] [--install-ssh-server]"; exit 0 ;;
    *) echo "Unknown option: $arg" >&2; exit 2 ;;
  esac
done
[ "$(uname -s)" = Linux ] || { echo "This bootstrap requires Linux." >&2; exit 1; }
arch=$(uname -m)
case "$arch" in x86_64|aarch64) ;; *) echo "Unsupported architecture: $arch" >&2; exit 1 ;; esac
[ -r /etc/os-release ] || { echo "Cannot detect distribution: /etc/os-release is missing." >&2; exit 1; }
. /etc/os-release
family="${ID:-} ${ID_LIKE:-}"
case " $family " in
  *' debian '*|*' ubuntu '*) manager=apt-get; packages='build-essential pkg-config libssl-dev curl ca-certificates git dpkg-dev rpm'; ssh_package=openssh-server; ssh_service=ssh ;;
  *' fedora '*|*' rhel '*|*' centos '*) manager=dnf; packages='gcc gcc-c++ make pkgconf-pkg-config openssl-devel curl ca-certificates git rpm-build systemd-rpm-macros'; ssh_package=openssh-server; ssh_service=sshd ;;
  *' arch '*) manager=pacman; packages='base-devel pkgconf openssl curl ca-certificates git'; ssh_package=openssh; ssh_service=sshd ;;
  *) echo "Unsupported distribution: ${PRETTY_NAME:-$family}. See DEVELOPMENT.md for manual prerequisites." >&2; exit 1 ;;
esac
command -v "$manager" >/dev/null 2>&1 || { echo "Expected $manager for $family, but it is missing." >&2; exit 1; }
echo "OpenGate Linux bootstrap: ${PRETTY_NAME:-Linux} ($arch)"
echo "System changes: refresh $manager metadata and install: $packages"
if command -v sshd >/dev/null 2>&1 || [ -x /usr/sbin/sshd ]; then
  echo 'OpenSSH Server: installed.'
else
  echo 'OpenSSH Server: not installed. Use --install-ssh-server to install and enable it.'
fi
if [ "$install_ssh" -eq 1 ]; then
  echo "Additional requested system changes: install $ssh_package and enable/start $ssh_service. This enables conventional SSH access subject to your firewall and SSH configuration."
  packages="$packages $ssh_package"
fi
export PATH="${CARGO_HOME:-$HOME/.cargo}/bin:$PATH"
if command -v rustup >/dev/null 2>&1; then
  echo 'Rust: rustup is available; ensure the stable toolchain with rustfmt and clippy.'
elif command -v cargo >/dev/null 2>&1; then
  echo 'Rust: using the existing system toolchain (the build verifies the required version).'
else
  echo 'User changes: install Rust stable from https://rustup.rs.'
fi
echo 'Build steps: cargo build --locked --release, cargo test --locked --workspace, then Linux packages where tools are available.'
[ "$apply" -eq 1 ] || { echo 'Dry run only. Re-run with --apply to perform these changes.'; exit 0; }
run_root() {
  if [ "$(id -u)" -eq 0 ]; then "$@"; else sudo -- "$@"; fi
}
# Package names are fixed above, never supplied by user input.
case "$manager" in
  apt-get) run_root apt-get update; run_root apt-get install -y $packages ;;
  dnf) run_root dnf install -y $packages ;;
  pacman) run_root pacman -Syu --needed --noconfirm $packages ;;
esac
if ! command -v cargo >/dev/null 2>&1; then
  download=$(mktemp)
  trap 'rm -f "$download"' EXIT HUP INT TERM
  curl --proto '=https' --tlsv1.2 -fsS https://sh.rustup.rs -o "$download"
  sh "$download" -y --profile minimal --default-toolchain stable
fi
if command -v rustup >/dev/null 2>&1; then
  rustup toolchain install stable --profile minimal --component rustfmt --component clippy
fi
if [ "$install_ssh" -eq 1 ]; then
  if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
    run_root systemctl enable --now "$ssh_service"
  else
    echo 'OpenSSH Server installed; enable it using the service manager on this machine.'
  fi
fi
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$root"
if command -v rustup >/dev/null 2>&1; then
  rustup run stable cargo build --locked --release
  rustup run stable cargo test --locked --workspace
else
  cargo build --locked --release
  cargo test --locked --workspace
fi
version=$(sed -n 's/^version = "\([^"]*\)"/\1/p' Cargo.toml | head -n 1)
scripts/package-linux.sh "$version" target/release/opengate
