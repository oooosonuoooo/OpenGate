Name: opengate
Version: %{version}
Release: 1%{?dist}
Summary: Secure peer-to-peer remote access daemon
License: Apache-2.0
BuildArch: x86_64
Requires(post): systemd

%description
Owner-authorized peer-to-peer remote access daemon.

%install
install -Dpm0755 %{binary} %{buildroot}%{_bindir}/opengate
install -Dpm0644 %{_sourcedir}/opengate.service %{buildroot}%{_unitdir}/opengate.service

%post
getent passwd opengate >/dev/null || useradd -r -d /var/lib/opengate -s /sbin/nologin opengate
%systemd_post opengate.service

%preun
%systemd_preun opengate.service

%postun
%systemd_postun_with_restart opengate.service

%files
%{_bindir}/opengate
%{_unitdir}/opengate.service
