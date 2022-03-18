Name:           tinc
Version:        __VERSION__
Release:        3%{?dist}
Summary:        A virtual private network daemon

License:        GPLv2+
URL:            https://www.tinc-vpn.org/

BuildRequires: gcc
BuildRequires: meson
BuildRequires: systemd
BuildRequires: openssl-devel
BuildRequires: lzo-devel
BuildRequires: zlib-devel
BuildRequires: lz4-devel
BuildRequires: ncurses-devel
BuildRequires: readline-devel

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
%define __meson_auto_features auto

%prep

%build
%meson
%meson_build

%install
%meson_install

%post
%systemd_post %{name}@.service

%preun
%systemd_preun %{name}@.service

%postun
%systemd_postun_with_restart %{name}@.service

%files
%doc AUTHORS COPYING.README NEWS README.md THANKS doc/sample*
%license COPYING
%{_mandir}/man*/%{name}*.*
%{_infodir}/%{name}.info.*
%{_sbindir}/%{name}
%{_sbindir}/%{name}d
%{_unitdir}/%{name}*.service
%{_datadir}/bash-completion/completions/%{name}
