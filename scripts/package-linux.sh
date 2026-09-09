#!/usr/bin/env sh
# Produces DEB and RPM inputs from a release binary; package managers perform installation.
set -eu
version=${1:?Usage: package-linux.sh VERSION [BINARY]}
binary=${2:-target/release/opengate}
[ -x "$binary" ] || { echo "Release binary missing: $binary" >&2; exit 1; }
root=target/package-root
rm -rf "$root"
mkdir -p "$root/usr/bin" "$root/lib/systemd/system" target/packages
install -m755 "$binary" "$root/usr/bin/opengate"
install -m644 packaging/linux/opengate.service "$root/lib/systemd/system/opengate.service"
if command -v dpkg-deb >/dev/null 2>&1; then
  mkdir -p "$root/DEBIAN"
  sed "s/@VERSION@/$version/g" packaging/debian/control > "$root/DEBIAN/control"
  install -m755 packaging/debian/postinst "$root/DEBIAN/postinst"
  dpkg-deb --build "$root" "target/packages/opengate_${version}_amd64.deb"
fi
if command -v rpmbuild >/dev/null 2>&1; then
  rpmbuild --define "_topdir $(pwd)/target/rpmbuild" --define "version $version" --define "binary $(realpath "$binary")" -bb packaging/rpm/opengate.spec
fi
