Summary: tinc vpn daemon
Name: tinc
Version: cvs_2000_04_17
Release: mk1
Copyright: GPL
Group: Networking
URL: http://tinc.nl.linux.org/
Source0: cabal.tgz
Source1: tinc
Buildroot: /var/tmp/%{name}-%{version}
#Requires: 

%description
tinc is cool!
See http://tinc.nl.linux.org/

%prep

%setup -q -n cabal

%build
autoconf
automake
./configure --prefix=/usr --sysconfdir=/etc
make

%install
ME=my.vpn.ip.number
PEER=peer.vpn.ip.number
PEEREAL=peer.real.ip.number

rm -rf $RPM_BUILD_ROOT

make install DESTDIR=$RPM_BUILD_ROOT

install -D $RPM_SOURCE_DIR/tinc $RPM_BUILD_ROOT/etc/rc.d/init.d/

mkdir -p $RPM_BUILD_ROOT/etc/tinc/$PEER/passphrases
cat <<END >$RPM_BUILD_ROOT/etc/tinc/$PEER/tincd.conf
#sample
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

%preun
%postun

%files

%doc AUTHORS ChangeLog NEWS README THANKS TODO

#%defattr(-,root,root)
%config /etc/tinc
/etc/rc.d
/usr/sbin
/usr/lib/tinc
/usr/man
/usr/info

%changelog
* Tue Apr 18 2000 Mads Kiileric <mads@kiilerich.com>
- initial rpm
