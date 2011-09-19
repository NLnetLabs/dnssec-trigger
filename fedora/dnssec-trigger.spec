Summary: NetworkManager plugin to update/reconfigure DNSSEC resolving
Name: dnssec-trigger
Version: 0.3
Release: 6%{?dist}
License: BSD
Url: http://www.nlnetlabs.nl/~wouter/dnssec-trigger/
Source: http://www.nlnetlabs.nl/~wouter/%{name}-%{version}.tar.gz
Source1: dnssec-triggerd.init

Group: System Environment/Daemons
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)
#BuildRequires: flex, openssl-devel , ldns-devel >= 1.5.0, 
#BuildRequires: NetworkManager-devel

Requires(post): chkconfig
Requires(preun): chkconfig
Requires(preun): initscripts
Requires(postun): initscripts
Requires: ldns >= 1.6.10, NetworkManager, unbound
Requires(pre): shadow-utils

%description
dnssec-trigger reconfigures the local unbound DNS server. This unbound DNS
server performs DNSSEC validation, but dnsesc-trigger will signal it to
to use the DHCP obtained forwarders if possible, and fallback to doing its
own AUTH queries if that fails, and if that fails prompt the user via
dnssec-trigger-applet the option to go with insecure DNS only.

%prep
%setup -q 

%build
%configure  
%{__make} %{?_smp_mflags}

%install
rm -rf %{buildroot}
%{__make} DESTDIR=%{buildroot} install
install -d 0755 %{buildroot}%{_initrddir}
install -m 0755 %{SOURCE1} %{buildroot}%{_initrddir}/dnssec-triggerd

%clean
rm -rf ${RPM_BUILD_ROOT}

%files 
%defattr(-,root,root,-)
%doc README
%attr(0755,root,root) %{_initrddir}/dnssec-triggerd
%ghost %attr(0755,root,root) %dir %{_localstatedir}/run/dnssec-triggerd
%attr(0755,root,root) %{_sysconfdir}/NetworkManager/dispatcher.d/01-dnssec-trigger-hook
%attr(0644,root,root) %config(noreplace) %{_sysconfdir}/dnssec-trigger.conf
%attr(0644,root,root) %config(noreplace) %{_sysconfdir}/xdg/autostart/dnssec-trigger-panel.desktop
%{_bindir}/dnssec-trigger-panel
%{_sbindir}/dnssec-trigger*
%{_mandir}/*/*
%attr(0755,root,root) %dir %{_datadir}/%{name}
%attr(0644,root,root) %config(noreplace) %{_datadir}/%{name}/*


%post
/sbin/chkconfig --add dnssec-triggerd

%preun
if [ "$1" -eq 0 ]; then
        /sbin/service dnssec-triggerd stop >/dev/null 2>&1
        /sbin/chkconfig --del dnssec-triggerd
fi

%postun 
if [ "$1" -ge "1" ]; then
  /sbin/service dnssec-triggerd condrestart >/dev/null 2>&1 || :
fi

%changelog
* Sat Sep 17 2011 Paul Wouters <paul@xelerance.com> - 0.3-6
- 01-dnssec-trigger-hook had no execute permissions

* Sat Sep 17 2011 Paul Wouters <paul@xelerance.com> - 0.3-5
- Start 01-dnssec-trigger-hook in daemon start
- Ensure dnssec-triggerd starts after NetworkManager

* Fri Sep 16 2011 Paul Wouters <paul@xelerance.com> - 0.3-4
- Initial package
