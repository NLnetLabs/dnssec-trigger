Summary: NetworkManager plugin to update/reconfigure DNSSEC resolving
Name: dnssec-trigger
Version: 0.10
Release: 3%{?dist}
License: BSD
Url: http://www.nlnetlabs.nl/downloads/dnssec-trigger/
Source: http://www.nlnetlabs.nl/downloads/dnssec-trigger/%{name}-%{version}.tar.gz
Source1:dnssec-triggerd.service
Source2: dnssec-triggerd-keygen.service
Source3: dnssec-trigger.conf
Requires(postun): initscripts
Requires: ldns >= 1.6.10, NetworkManager
Requires(pre): shadow-utils
BuildRequires: desktop-file-utils systemd-units, openssl-devel, ldns-devel
BuildRequires: gtk2-devel, NetworkManager-devel

Requires(post): systemd-sysv
Requires(post): systemd-units
Requires(preun): systemd-units
Requires(postun): systemd-units

%description
dnssec-trigger reconfigures the local unbound DNS server. This unbound DNS
server performs DNSSEC validation, but dnssec-trigger will signal it to
use the DHCP obtained forwarders if possible, and fallback to doing its
own AUTH queries if that fails, and if that fails prompt the user via
dnssec-trigger-applet the option to go with insecure DNS only.

%prep
%setup -q 
# Fixup the name to not include "panel" in the menu item or name
sed -i "s/ Panel//" panel/dnssec-trigger-panel.desktop.in
sed -i "s/-panel//" panel/dnssec-trigger-panel.desktop.in
# NM has no /usr/sbin in path
sed -i "s/^dnssec-trigger-control/\/usr\/sbin\/dnssec-trigger-control/" 01-dnssec-trigger-hook.sh.in

%build
%configure  --with-keydir=/etc/dnssec-trigger 
%{__make} %{?_smp_mflags}

%install
rm -rf %{buildroot}
%{__make} DESTDIR=%{buildroot} install
install -d 0755 %{buildroot}%{_unitdir}
install -m 0644 %{SOURCE1} %{buildroot}%{_unitdir}/%{name}d.service
install -m 0644 %{SOURCE2} %{buildroot}%{_unitdir}/%{name}d-keygen.service
install -m 0644 %{SOURCE3} %{buildroot}%{_sysconfdir}/%{name}/

desktop-file-install --dir=%{buildroot}%{_datadir}/applications dnssec-trigger-panel.desktop

# supress the panel name everywhere including the gnome3 panel at the bottom
ln -s dnssec-trigger-panel %{buildroot}%{_bindir}/dnssec-trigger

%clean
rm -rf ${RPM_BUILD_ROOT}

%files 
%defattr(-,root,root,-)
%doc README LICENSE
%{_unitdir}/%{name}d.service
%{_unitdir}/%{name}d-keygen.service

%attr(0755,root,root) %dir %{_sysconfdir}/%{name}
%attr(0755,root,root) %{_sysconfdir}/NetworkManager/dispatcher.d/01-dnssec-trigger-hook
%attr(0644,root,root) %config(noreplace) %{_sysconfdir}/%{name}/dnssec-trigger.conf
%attr(0644,root,root) %config(noreplace) %{_sysconfdir}/xdg/autostart/dnssec-trigger-panel.desktop
%{_bindir}/dnssec-trigger-panel
%{_bindir}/dnssec-trigger
%{_sbindir}/dnssec-trigger*
%{_mandir}/*/*
%attr(0755,root,root) %dir %{_datadir}/%{name}
%attr(0644,root,root) %{_datadir}/%{name}/*
%attr(0644,root,root) %{_datadir}/applications/dnssec-trigger-panel.desktop


%post
# Enable (but don't start) the units by default
    /bin/systemctl enable %{name}d.service >/dev/null 2>&1 || :
    /bin/systemctl enable %{name}d-keygen.service >/dev/null 2>&1 || :


%preun
if [ "$1" -eq "0" ] ; then
    # Package removal, not upgrade
    /bin/systemctl --no-reload disable %{name}d.service > /dev/null 2>&1 || :
    /bin/systemctl --no-reload disable %{name}d-keygen.service > /dev/null 2>&1 || :
    /bin/systemctl stop %{name}d.service >/dev/null 2>&1 || :
    /bin/systemctl stop %{name}d-keygen.service >/dev/null 2>&1 || :
    # dnssec-triggerd makes /etc/resolv.conf immutable, undo that on removal
    chattr -i /etc/resolv.conf
fi

%postun 
    /bin/systemctl daemon-reload >/dev/null 2>&1 || :

%changelog
* Wed Feb 22 2012 Paul Wouters <pwouters@redhat.com> - 0.10-3
- Fix the systemd startup to require unbound
- dnssec-triggerd no longer forks, giving systemd more control
- Fire NM dispatcher in ExecStartPost of dnssec-triggerd.service
- Fix tcp80 entries in dnssec-triggerd.conf
- symlink dnssec-trigger-panel to dnssec-trigger to supress the
  "-panel" in the applet name shown in gnome3

* Wed Feb 22 2012 Paul Wouters <pwouters@redhat.com> - 0.10-2
- The NM hook was not modified at the right time during build

* Wed Feb 22 2012 Paul Wouters <pwouters@redhat.com> - 0.10-1
- Updated to 0.10
- The NM hook lacks /usr/sbin in path, resulting in empty resolv.conf on hotspot

* Wed Feb 08 2012 Paul Wouters <pwouters@redhat.com> - 0.9-4
- Updated tls443 / tls80 resolver instances supplied by Fedora Hosted

* Mon Feb 06 2012 Paul Wouters <pwouters@redhat.com> - 0.9-3
- Convert from SysV to systemd for initial Fedora release
- Moved configs and pem files to /etc/dnssec-trigger/
- No more /var/run/dnssec-triggerd/
- Fix Build-requires
- Added commented tls443 port80 entries of pwouters resolvers
- On uninstall ensure there is no immutable bit on /etc/resolv.conf

* Sat Jan 07 2012 Paul Wouters <paul@xelerance.com> - 0.9-2
- Added LICENCE to doc section

* Mon Dec 19 2011 Paul Wouters <paul@xelerance.com> - 0.9-1
- Upgraded to 0.9

* Fri Oct 28 2011 Paul Wouters <paul@xelerance.com> - 0.7-1
- Upgraded to 0.7

* Fri Sep 23 2011 Paul Wouters <paul@xelerance.com> - 0.4-1
- Upgraded to 0.4

* Sat Sep 17 2011 Paul Wouters <paul@xelerance.com> - 0.3-5
- Start 01-dnssec-trigger-hook in daemon start
- Ensure dnssec-triggerd starts after NetworkManager

* Fri Sep 16 2011 Paul Wouters <paul@xelerance.com> - 0.3-4
- Initial package
