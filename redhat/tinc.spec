Summary: tinc Virtual Private Network daemon
Name: tinc
Version: 1.0pre1
Release: 2
Copyright: GPL
Group: System Environment/Daemons
URL: http://tinc.nl.linux.org/
Source0: %{name}-%{version}.tar.gz
Buildroot: /var/tmp/%{name}-%{version}-%{release}
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
128 0c647a1fd34da9d04c1d340ae9363f31
END
cat <<END >$RPM_BUILD_ROOT/etc/tinc/$PEER/passphrases/$PEER
128 aea5a5d414fea63ee3829b592afc0fba
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
+ tinc		655/udp		TINC		# tinc.nl.linux.org
  #
  # UNIX specific services
END

grep -q '^alias tap0' /etc/conf.modules || cat >> /etc/conf.modules << END
# tinc uses ethertap/netlink
alias tap0 ethertap
alias char-major-36 netlink_dev
END
/sbin/install-info /usr/info/tinc.info.gz /usr/info/dir --entry= \
	"* tinc: (tinc).				The tinc Manual."

%preun
%postun

%files
%doc AUTHORS ChangeLog NEWS README THANKS *.html doc/tincd.conf.sample
%config /etc/tinc/
/etc/rc.d/init.d/tinc
/usr/sbin/genauth
/usr/sbin/tincd
/usr/lib/tinc/
/usr/man/man5/tincd.conf.5
/usr/man/man8/genauth.8
/usr/man/man8/tincd.8
/usr/info/tinc.info.gz
