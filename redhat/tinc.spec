Summary: tinc Virtual Private Network daemon
Name: tinc
Version: 1.0pre1
Release: 2
Copyright: GPL
Group: System Environment/Daemons
URL: http://tinc.nl.linux.org/
Source0: %{name}-%{version}.tar.gz
Buildroot: /var/tmp/%{name}-%{version}-%{release}
Requires: iproute
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

%setup -q -n %{name}-%{version}

%build
./configure --prefix=/usr --sysconfdir=/etc
make
/usr/bin/texi2html doc/tinc.texi

%install
rm -rf $RPM_BUILD_ROOT
make install DESTDIR=$RPM_BUILD_ROOT
gzip $RPM_BUILD_ROOT/usr/info/tinc.info

mkdir -p $RPM_BUILD_ROOT/etc/rc.d/init.d/
cp redhat/tinc $RPM_BUILD_ROOT/etc/rc.d/init.d/

ME=my.vpn.ip.number
PEER=peer.vpn.ip.number
PEEREAL=peer.real.ip.number

umask 077
mkdir -p $RPM_BUILD_ROOT/etc/tinc/$PEER/passphrases
cat <<END >$RPM_BUILD_ROOT/etc/tinc/$PEER/tinc.conf
# Sample tinc configuration. 
# Insert your own ip numbers instead of the placeholders,
# and be sure to use your own passphrases.
# See man tinc.conf(5) tincd(8) genauth(8), info tinc and 
# /usr/doc/%{name}-%{version}/tinc.conf.sample
TapDevice = /dev/tap0
ConnectTo = $PEEREAL
MyVirtualIP = $ME/32
AllowConnect = no
END
cat <<END >$RPM_BUILD_ROOT/etc/tinc/$PEER/passphrases/local
1024 c1da5b633b428d783fec96ac89bb6bd4ed97ac673942706ba2240cde977158b7cd5f4055b7db70a7365d1f8df6a1a7c9dbb73f4e2bf8484fc14aee68d0f950e2bce82dd2a6386f040546a61e77cd1c25265ce03182e4e2c9a00ae0ea2f1f89ac04a10f7b67312187b5d2d74618803974ba6f053116b1460bc194c652dc28c84a
END
cat <<END >$RPM_BUILD_ROOT/etc/tinc/$PEER/passphrases/$PEER
1024 9dff58799827c3ae73699d9d4029cf80ee4cfd3a8408495cdb68c78dec602c46f362aedeea80928384254bc7d0bfbf9756c0783b5ec9943161863530a8861947147d124286e8c46fd98af988c96ba65c63acefc01f6c03b6b8f7d9897acb02c083adb7416ee5ccbc19610a8b9ade2599d8f66e94c715f2e1a15054a78a3f3260
END

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
END
/sbin/install-info /usr/info/tinc.info.gz /usr/info/dir 

%preun
/sbin/install-info --delete /usr/info/tinc.info.gz /usr/info/dir

%postun

%files
%doc AUTHORS ChangeLog NEWS README THANKS *.html doc/tinc.conf.sample
%config /etc/tinc/
%attr(0755,root,root) /etc/rc.d/init.d/tinc
/usr/sbin/genauth
/usr/sbin/tincd
/usr/lib/tinc/
/usr/man/man5/tinc.conf.5
/usr/man/man8/genauth.8
/usr/man/man8/tincd.8
/usr/info/tinc.info.gz
