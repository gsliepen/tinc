#! /usr/bin/perl -w
#
# System startup script for tinc
# $Id: init.d,v 1.9 2000/05/19 01:17:32 zarq Exp $
#
# Based on Lubomir Bulej's Redhat init script.
#
# Create a file $NETSFILE (/etc/tinc/nets.boot), and put all the names of
# the networks in there.  These names must be valid directory names under
# $TCONF (/etc/tinc).  Lines starting with a # will be ignored in this
# file.
#

my $DAEMON="/usr/sbin/tincd";
my $NAME="tinc";
my $DESC="tinc daemons";
my $TCONF="/etc/tinc";
my $EXTRA="";
my $NETSFILE="$TCONF/nets.boot";
my @NETS=();


if (! -f $DAEMON) { exit 0; }



sub find_nets {
    if(! open(FH, $NETSFILE)) {
	warn "Please create $NETSFILE.\n";
	exit 0;
    }
    while (<FH>) {
	chomp;
	if( /^[ ]*([^ \#]+)/i ) {
	    push(@NETS, "$1");
	}
    }
    if($#NETS == -1) {
	warn "$NETSFILE doesn't contain any nets.\n";
	exit 0;
    }
    
}


##############################################################################
# vpn_load ()		Loads VPN configuration
# 
# $_[0] ... VPN to load

sub vpn_load {
    my @addr;
    $CFG="$TCONF/$_[0]/tinc.conf";
    if(! open($CFG, "< $CFG")) {
	warn "tinc: $CFG does not exist\n";
	return 0;
    }

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
	warn "tinc: There must be a TapDevice\n";
	return 0;
    }
    if($DEV eq "") {
	warn "tinc: TapDevice should be of the form /dev/tapN\n";
	return 0;
    }
    if(!defined($VPN)) {
	warn "tinc: MyVirtualIP required\n";
	return 0;
    }
    if($VPN eq "") {
	warn "tinc: No argument to MyVirtualIP/MyOwnVPNIP\n";
	return 0;
    }
    if(defined($VPNMASK) && $VPNMASK eq "") {
	warn "tinc: Invalid argument to VpnMask\n";
	return 0;
    }
    $ADR = $VPN;
    $ADR =~ s/^([^\/]+)\/.*$/$1/;
    $LEN = $VPN;
    $LEN =~ s/^.*\/([^\/]+)$/$1/;
    if($ADR eq "" || $LEN eq "") {
	warn "tinc: Badly formed MyVirtualIP/MyOwnVPNIP\n";
	return 0;
    }
    @addr = split(/\./, $ADR);

    $ADR = pack('C4', @addr);
    $MSK = pack('N4', -1 << (32 - $LEN));
    $BRD = join(".", unpack('C4', $ADR | ~$MSK));
#    $NET = join(".", unpack('C4', $ADR & $MSK));
    $MAC = "fe:fd:" . join(":", map { sprintf "%02x", $_ } unpack('C4', $ADR));
    $VPNMASK = pack('C4', split(/\./, $VPNMASK));
    $VPNNET = join(".", unpack('C4', $ADR & $VPNMASK));
    $VPNMASK = join(".", unpack('C4', $VPNMASK));
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
    vpn_load($_[0]) || return 0;

    system("insmod ethertap -s --name=\"ethertap$NUM\" unit=\"$NUM\" >/dev/null");
    system("ifconfig $DEV hw ether $MAC");
    system("ifconfig $DEV $ADR netmask $MSK broadcast $BRD -arp");
    system("start-stop-daemon --start --quiet --pidfile /var/run/$NAME.$_[0].pid --exec $DAEMON -- -n $_[0] $EXTRA");
    if(defined($VPNMASK)) {
	system("route add -net $VPNNET netmask $VPNMASK dev $DEV");
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
    find_nets;
    print "Starting $DESC:";
    foreach $n (@NETS) {
	print " $n";
	vpn_start($n);
    }
    print ".\n";
} elsif ($ARGV[0] eq "stop") {
    find_nets;
    print "Stopping $DESC:";
    foreach $n (@NETS) {
	print " $n";
	vpn_stop($n);
    }
    print ".\n";
} elsif ($ARGV[0] eq "restart" || $ARGV[0] eq "force-reload") {
    find_nets;
    print "Stopping $DESC:";
    foreach $n (@NETS) {
	print " $n";
	vpn_stop($n);
    }
    print ".\n";
    print "Starting $DESC:";
    foreach $n (@NETS) {
	print " $n";
	vpn_start($n);
    }
    print ".\n";
} else {
    die "Usage: /etc/init.d/$NAME {start|stop|restart|force-reload}\n";
}    
