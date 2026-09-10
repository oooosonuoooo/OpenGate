Name: opengate
Version: %{version}
Release: 1%{?dist}
Summary: Secure peer-to-peer remote access daemon
License: Apache-2.0
Requires(pre): shadow-utils
Requires(post): systemd
Source0: opengate.service
Source1: LICENSE
Source2: README.md

%description
Owner-authorized peer-to-peer remote access daemon.

%install
install -Dpm0755 "%{binary}" %{buildroot}%{_bindir}/opengate
install -Dpm0644 %{SOURCE0} %{buildroot}%{_unitdir}/opengate.service
install -Dpm0644 %{SOURCE1} %{buildroot}%{_datadir}/licenses/opengate/LICENSE
install -Dpm0644 %{SOURCE2} %{buildroot}%{_docdir}/opengate/README.md

%pre
getent passwd opengate >/dev/null || useradd -r -U -d /var/lib/opengate -s /sbin/nologin opengate

%post
if [ -d /run/systemd/system ]; then
    systemctl daemon-reload
    systemctl enable opengate.service >/dev/null 2>&1 || :
    systemctl restart opengate.service || echo "OpenGate could not start; inspect journalctl -u opengate.service." >&2
fi

%preun
if [ "$1" -eq 0 ] && [ -d /run/systemd/system ]; then
    systemctl stop opengate.service || :
    systemctl disable opengate.service >/dev/null 2>&1 || :
fi

%postun
if [ -d /run/systemd/system ]; then
    systemctl daemon-reload
fi
# Configuration, identity, shared files and the service account are preserved.

%files
%{_bindir}/opengate
%{_unitdir}/opengate.service

%license %{_datadir}/licenses/opengate/LICENSE
%doc %{_docdir}/opengate/README.md
