#! /usr/bin/perl -w
#
# System startup script for tinc
# $Id: init.d,v 1.6 2000/05/16 14:34:44 zarq Exp $
#
# Based on Lubomir Bulej's Redhat init script.
#

my $DAEMON="/usr/sbin/tincd";
my $NAME="tinc";
my $DESC="tinc daemons";
my $TCONF="/etc/tinc";
my $EXTRA="";

# Put your VPN names in here.
my $NETS="";  # This is a space-separated list of networks to be started.


if (! -f $DAEMON) { exit 0; }

if ($NETS eq "") {
    warn "Please edit /etc/init.d/tinc before attempting to start tinc.\n";
    exit 0;
}

##############################################################################
# vpn_load ()		Loads VPN configuration
# 
# $_[0] ... VPN to load


sub vpn_load {
    my @addr;
    $CFG="$TCONF/$_[0]/tinc.conf";
    open($CFG, "< $CFG") || die "tinc: $CFG does not exist";

    # load TINCD config
    while(<$CFG>) {
	if( /^[ ]*TapDevice[ =]+([^ \#]+)/i ) {
	    $DEV=$1;
	    chomp($DEV);
	    $DEV =~ s/^.*\/([^\/0-9]+)([0-9]+)$/$1$2/;
	    $NUM = $2;
	} elsif ( /^[ ]*(MyOwnVPNIP|MyVirtualIP)[ =]+([^ \#]+)/i ) {
	    $VPN=$2;
	    chomp($VPN);
	} elsif ( /^[ ]*VpnMask[ =]+([^ \#]+)/i ) {
	    $VPNMASK=$1;
	}
    }
    if(!defined($DEV)) {
	die "tinc: There must be a TapDevice";
    }
    if($DEV eq "") {
	die "tinc: TapDevice should be of the form /dev/tapN";
    }
    if(!defined($VPN)) {
	die "tinc: MyVirtualIP required";
    }
    if($VPN eq "") {
	die "tinc: No argument to MyVirtualIP/MyOwnVPNIP";
    }
    if(defined($VPNMASK) && $VPNMASK eq "") {
	die "tinc: Invalid argument to VpnMask";
    }
    $ADR = $VPN;
    $ADR =~ s/^([^\/]+)\/.*$/$1/;
    $LEN = $VPN;
    $LEN =~ s/^.*\/([^\/]+)$/$1/;
    if($ADR eq "" || $LEN eq "") {
	die "tinc: Badly formed MyVirtualIP/MyOwnVPNIP";
    }
    @addr = split(/\./, $ADR);

    $ADR = pack('C4', @addr);
    $MSK = pack('N4', -1 << (32 - $LEN));
    $BRD = join(".", unpack('C4', $ADR | ~$MSK));
#    $NET = join(".", unpack('C4', $ADR & $MSK));
    $MAC = "fe:fd:" . join(":", map { sprintf "%02x", $_ } unpack('C4', $ADR));
    $ADR = join(".", unpack('C4', $ADR));
    $MSK = join(".", unpack('C4', $MSK));
    
#    print "$DEV $VPN $NUM $LEN @addr $MAC $MASK $BRD $NET\n";

    1;
}


##############################################################################
# vpn_start ()		starts specified VPN
# 
# $_[0] ... VPN to start

sub vpn_start {
    vpn_load($_[0]) || die "tinc: could not vpn_load $_[0]";

    system("insmod ethertap -s --name=\"ethertap$NUM\" unit=\"$NUM\" >/dev/null");
    system("ifconfig $DEV hw ether $MAC");
    system("ifconfig $DEV $ADR netmask $MSK broadcast $BRD -arp");
    system("start-stop-daemon --start --quiet --pidfile /var/run/$NAME.$_[0].pid --exec $DAEMON -- -n $_[0] $EXTRA");
    if(defined($VPNMASK)) {
	system("route add -net $ADR netmask $VPNMASK dev $DEV");
    }
}




##############################################################################
# vpn_stop ()		Stops specified VPN
#
# $_[0] ... VPN to stop

sub vpn_stop {
    vpn_load($_[0]) || return 1;

    system("start-stop-daemon --stop --quiet --pidfile /var/run/$NAME.$_[0].pid --exec $DAEMON -- -n $_[0] $EXTRA -k");
    
    system("ifconfig $DEV down");
    system("rmmod ethertap$NUM -s");
}


if(!defined($ARGV[0])) {
    die "Usage: /etc/init.d/$NAME {start|stop|restart|force-reload}\n";
}

if($ARGV[0] eq "start") {
    print "Starting $DESC:";
    foreach $n (split(" ", $NETS)) {
	print " $n";
	vpn_start($n);
    }
    print ".\n";
} elsif ($ARGV[0] eq "stop") {
    print "Stopping $DESC:";
    foreach $n (split(" ", $NETS)) {
	print " $n";
	vpn_stop($n);
    }
    print ".\n";
} elsif ($ARGV[0] eq "restart" || $ARGV[0] eq "force-reload") {
    print "Stopping $DESC:";
    foreach $n (split(" ", $NETS)) {
	print " $n";
	vpn_stop($n);
    }
    print ".\n";
    print "Starting $DESC:";
    foreach $n (split(" ", $NETS)) {
	print " $n";
	vpn_start($n);
    }
    print ".\n";
} else {
    die "Usage: /etc/init.d/$NAME {start|stop|restart|force-reload}\n";
}    
