#! /usr/bin/perl -w
#
# System startup script for tinc
# $Id: init.d,v 1.14.2.3 2000/10/31 16:22:49 guus Exp $
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

if(!defined($ARGV[0])) {
    die "Usage: /etc/init.d/$NAME {start|stop|restart|force-reload}\n";
}

if($ARGV[0] eq "start") {
    find_nets;
    print "Starting $DESC:";
    foreach $n (@NETS) {
	print " $n";
        system("$DAEMON -n $_[0] $EXTRA");
    }
    print ".\n";
} elsif ($ARGV[0] eq "stop") {
    find_nets;
    print "Stopping $DESC:";
    foreach $n (@NETS) {
	print " $n";
        system("$DAEMON -n $_[0] $EXTRA -k");
    }
    print ".\n";
} elsif ($ARGV[0] eq "restart" || $ARGV[0] eq "force-reload") {
    find_nets;
    print "Stopping $DESC:";
    foreach $n (@NETS) {
	print " $n";
        system("$DAEMON -n $_[0] $EXTRA -k");
    }
    print ".\n";
    print "Starting $DESC:";
    foreach $n (@NETS) {
	print " $n";
        system("$DAEMON -n $_[0] $EXTRA");
    }
    print ".\n";
} else {
    die "Usage: /etc/init.d/$NAME {start|stop|restart|force-reload}\n";
}    
