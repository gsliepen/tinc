Summary: tinc Virtual Private Network daemon
Name: tinc
Version: 1.0
Release: cvs
Copyright: GPL
Group: System Environment/Daemons
URL: http://tinc.nl.linux.org/
Source0: %{name}-%{version}-%{release}.tar.gz
Buildroot: /var/tmp/%{name}
#-%{version}-%{release}
#Requires: iproute
# for building the package the following is required:
# /usr/bin/texi2html /usr/bin/patch

%description
# taken from doc/tinc.texi
tinc is a Virtual Private Network (VPN) daemon that uses tunneling and
encryption to create a secure private network between hosts on the
Internet.

Because the tunnel appears to the IP level network code as a normal
network device, there is no need to adapt any existing software.

This tunneling allows VPN sites to share information with each other
over the Internet without exposing any information to others.

See http://tinc.nl.linux.org/

%prep

%setup -q -n %{name}-%{version}-%{release}

%build
./configure --prefix=/usr --sysconfdir=/etc --localstatedir=/var
make
/usr/bin/texi2html doc/tinc.texi

%install
rm -rf $RPM_BUILD_ROOT
make install DESTDIR=$RPM_BUILD_ROOT
gzip $RPM_BUILD_ROOT/usr/info/tinc.info

mkdir -p $RPM_BUILD_ROOT/etc/rc.d/init.d/
cp redhat/tinc $RPM_BUILD_ROOT/etc/rc.d/init.d/

mkdir -p $RPM_BUILD_ROOT/etc/tinc/
touch $RPM_BUILD_ROOT/etc/tinc/nets.boot

%clean
rm -rf $RPM_BUILD_ROOT

%pre
%post

/sbin/chkconfig --add tinc

grep -q '^tinc[[:space:]]' /etc/services || patch -s /etc/services << END
*** services.org        Tue Apr 18 13:22:22 2000
--- services    Tue Apr 18 13:24:19 2000
***************
*** 145,148 ****
--- 145,150 ----
  hmmp-ind	612/tcp		dqs313_intercell# HMMP Indication / DQS
  hmmp-ind	612/udp		dqs313_intercell# HMMP Indication / DQS
+ tinc		655/tcp		TINC		# tinc vpn
+ tinc		655/udp		TINC		# http://tinc.nl.linux.org/
  #
  # UNIX specific services
END

grep -q '^alias tap0' /etc/conf.modules || cat >> /etc/conf.modules << END
# tinc uses ethertap/netlink
alias tap0 ethertap
alias char-major-36 netlink_dev
alias char-major-10-200 tun
END
/sbin/install-info /usr/info/tinc.info.gz /usr/info/dir 

%preun
/sbin/install-info --delete /usr/info/tinc.info.gz /usr/info/dir

%postun

%files
%doc AUTHORS ChangeLog NEWS README THANKS *.html
%config /etc/tinc/
%attr(0755,root,root) /etc/rc.d/init.d/tinc
/usr/sbin/tincd
/usr/man/man5/tinc.conf.5
/usr/man/man8/tincd.8
/usr/info/tinc.info.gz
