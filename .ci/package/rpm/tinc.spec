Name:           tinc
Version:        __VERSION__
Release:        3%{?dist}
Summary:        A virtual private network daemon

License:        GPLv2+
URL:            https://www.tinc-vpn.org/

BuildRequires: systemd

Requires(post):   systemd
Requires(preun):  systemd
Requires(postun): systemd

%description
tinc is a Virtual Private Network (VPN) daemon that uses tunnelling
and encryption to create a secure private network between hosts on
the Internet. Because the tunnel appears to the IP level network
code as a normal network device, there is no need to adapt any
existing software. This tunnelling allows VPN sites to share
information with each other over the Internet without exposing any
information to others.

%define debug_package %{nil}

%prep

%build
%configure --with-systemd=%{_unitdir} __CONFIGURE_ARGS__
%make_build

%install
%make_install
rm -f %{buildroot}%{_infodir}/dir

%post
%systemd_post %{name}@.service

%preun
%systemd_preun %{name}@.service

%postun
%systemd_postun_with_restart %{name}@.service

%files
%doc AUTHORS COPYING.README NEWS README THANKS doc/sample* doc/*.tex
%license COPYING
%{_mandir}/man*/%{name}*.*
%{_infodir}/%{name}.info.*
%{_sbindir}/%{name}
%{_sbindir}/%{name}d
%{_unitdir}/%{name}*.service
%{_datadir}/bash-completion/completions/%{name}
