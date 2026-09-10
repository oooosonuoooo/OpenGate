#!/usr/bin/env sh
# Produces installable DEB and RPM artifacts from a compiled release binary.
set -eu
version=${1:?Usage: package-linux.sh VERSION [BINARY]}
binary=${2:-target/release/opengate}
[ -x "$binary" ] || { echo "Release binary missing: $binary" >&2; exit 1; }
case "$version" in *[!0-9A-Za-z.+~_-]*|'') echo "Invalid package version: $version" >&2; exit 2 ;; esac

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
binary=$(CDPATH= cd -- "$(dirname -- "$binary")" && pwd)/$(basename -- "$binary")
out="$root/target/packages"
work="$root/target/package-root"
rm -rf "$work"
mkdir -p "$out" "$work/deb/usr/bin" "$work/deb/lib/systemd/system" "$work/deb/usr/share/doc/opengate"
trap 'rm -rf "$work"' EXIT HUP INT TERM

install -m755 "$binary" "$work/deb/usr/bin/opengate"
install -m644 "$root/packaging/linux/opengate.service" "$work/deb/lib/systemd/system/opengate.service"

install -m644 "$root/LICENSE" "$root/README.md" "$work/deb/usr/share/doc/opengate/"

if command -v dpkg-deb >/dev/null 2>&1; then
  command -v dpkg-shlibdeps >/dev/null 2>&1 || { echo "dpkg-shlibdeps is required to record accurate runtime library dependencies (install dpkg-dev)." >&2; exit 1; }
  arch=$(dpkg --print-architecture)
  mkdir -p "$work/shlibs/debian"
  # dpkg-shlibdeps needs a source control file; create it only in the build area.
  printf 'Source: opengate\n\nPackage: opengate\nArchitecture: any\nDescription: OpenGate\n' > "$work/shlibs/debian/control"
  dependencies=$(cd "$work/shlibs" && dpkg-shlibdeps -O -e"$binary")
  dependencies=${dependencies#shlibs:Depends=}
  [ -n "$dependencies" ] || { echo "Could not determine runtime dependencies." >&2; exit 1; }
  mkdir -p "$work/deb/DEBIAN"
  sed -e "s/@VERSION@/$version/g" -e "s/^Architecture: .*/Architecture: $arch/" -e "s/^Depends: .*/Depends: adduser, systemd, $dependencies/" "$root/packaging/debian/control" > "$work/deb/DEBIAN/control"
  for hook in postinst prerm postrm; do
    install -m755 "$root/packaging/debian/$hook" "$work/deb/DEBIAN/$hook"
  done
  dpkg-deb --root-owner-group --build "$work/deb" "$out/opengate_${version}_${arch}.deb"
else
  echo "dpkg-deb is unavailable; DEB was not built." >&2
fi

if command -v rpmbuild >/dev/null 2>&1; then
  rpmroot="$work/rpm"
  mkdir -p "$rpmroot/BUILD" "$rpmroot/BUILDROOT" "$rpmroot/RPMS" "$rpmroot/SOURCES" "$rpmroot/SPECS" "$rpmroot/SRPMS"
  install -m644 "$root/packaging/linux/opengate.service" "$rpmroot/SOURCES/opengate.service"
  install -m644 "$root/LICENSE" "$root/README.md" "$rpmroot/SOURCES/"
  rpmbuild --define "_topdir $rpmroot" --define "version $version" --define "binary $binary" --define "_unitdir /usr/lib/systemd/system" -bb "$root/packaging/rpm/opengate.spec"
  find "$rpmroot/RPMS" -type f -name '*.rpm' -exec install -m644 {} "$out/" \;
else
  echo "rpmbuild is unavailable; RPM was not built." >&2
fi

# A portable binary archive is useful on distributions without DEB/RPM tooling.
portable="$work/opengate-$version-linux-$(uname -m)"
mkdir -p "$portable"
install -m755 "$binary" "$portable/opengate"
install -m644 "$root/LICENSE" "$root/README.md" "$root/INSTALL-LINUX.md" "$portable/"
tar -C "$work" -czf "$out/$(basename "$portable").tar.gz" "$(basename "$portable")"
(cd "$out" && find . -maxdepth 1 -type f \( -name '*.deb' -o -name '*.rpm' -o -name '*.tar.gz' \) -exec sha256sum {} + | sort > SHA256SUMS)
