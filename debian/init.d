#! /bin/sh -x
#
# skeleton	example file to build /etc/init.d/ scripts.
#		This file should be used to construct scripts for /etc/init.d.
#
#		Written by Miquel van Smoorenburg <miquels@cistron.nl>.
#		Modified for Debian GNU/Linux
#		by Ian Murdock <imurdock@gnu.ai.mit.edu>.
#
# Version:	@(#)skeleton  1.8  03-Mar-1998  miquels@cistron.nl
#
# This file was automatically customized by dh-make on Fri, 21 Apr 2000 17:07:50 +0200

PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
DAEMON=/usr/sbin/tincd
NAME=tinc
DESC="tinc daemons"
NETS="test2"

TCONF="/etc/tinc"

test -f $DAEMON || exit 0

set -e

# Check the daemon
if [ ! -x $TINCD ]; then
    echo "**tinc: daemon $TINCD does not exist or is not executable!"
    exit
fi

# Check the configuration directory
if [ ! -d $TCONF ]; then
    echo "**tinc: configuration directory ($TCONF) not found!"
    exit
fi


##############################################################################
# vpn_load ()		Loads VPN configuration
# 
# $1 ... VPN to load


vpn_load () {
    CFG="$TCONF/$1/tinc.conf"
    [ -f $CFG ] || { echo "tinc: $CFG does not exist" >&2 ; return 1; }

    # load TINCD config
    DEV=`grep -i -e '^[[:space:]]*TapDevice' $CFG | sed 's/[[:space:]]//g; s/^.*=//g'`
    VPN=`grep -i -e '^[[:space:]]*(MyOwnVPNIP|MyVirtualIP)' -E $CFG | head -1 | sed 's/[[:space:]]//g; s/^.*=//g'`

    # discourage empty and multiple entries
    [ -z "$DEV" ] && \
	{ echo "tinc: TapDevice required" >&2 ; return 2; }
    echo $DEV | grep -q '^/dev/tap' ||
	{ echo "tinc: TapDevice should be in form /dev/tapX" >&2 ; return 2; }
    [ `echo $DEV | wc -l` -gt 1 ] &&
	{ echo "tinc: multiple TapDevice entries not allowed" >&2 ; return 3; }
    [ -z "$VPN" ] && \
	{ echo "tinc: MyOwnVPNIP/MyVirtualIP required" >&2 ; return 2; }
    [ `echo $VPN | wc -l` -gt 1 ] &&
	{ echo "tinc: multiple MyOwnVPNIP/MyVirtualIP entries not allowed" >&2 ; return 3; }
    echo $VPN | grep -q -x \
	'\([[:digit:]]\{1,3\}\.\)\{3\}[[:digit:]]\{1,3\}/[[:digit:]]\{1,2\}' || \
	{ echo "tinc: badly formed MyOwnVPNIP/MyVirtualIP address $VPN" ; return 3; }

    # network device
    TAP=`echo $DEV | cut -d"/" -f3`
    NUM=`echo $TAP | sed 's/tap//'`
	    
    # IP address, netmask length
    ADR=`echo $VPN | cut -d"/" -f1`
    LEN=`echo $VPN | cut -d"/" -f2`
	    
    # Expand bitlength to netmask    
    MSK=""; len=$LEN
    for cnt in 1 1 1 0 ; do
	if [ $len -ge 8 ]; then
	    msk=8
	else
	    msk=$len
	fi
	
	MSK="$MSK$((255 & (255 << (8 - msk))))"
	[ $cnt -ne 0 ] && MSK="$MSK."
	len=$((len-msk))
    done

    # Network & broadcast addresses
#    BRD=`ipcalc --broadcast $ADR $MSK | cut -d"=" -f2`
#    NET=`ipcalc --network $ADR $MSK | cut -d"=" -f2`
	    
    # MAC address
    MAC=`printf "fe:fd:%0.2x:%0.2x:%0.2x:%0.2x" $(echo $ADR | sed 's/\./ /g')`
    echo
    echo "TAP $TAP NUM $NUM ADR $ADR LEN $LEN MSK $MSK BRD $BRD NET $NET MAC $MAC" >&2
    return 0
}


##############################################################################
# vpn_start ()		starts specified VPN
# 
# $1 ... VPN to start

vpn_start () {    

    vpn_load $1 || { echo "**tinc: could not vpn_load $1" >&2 ; return 1; }
            
    # create device file
    if [ ! -c $DEV ]; then
	[ -e $DEV ] && rm -f $DEV
	mknod --mode=0600 $DEV c 36 $((16 + NUM))
    fi
    
    # load device module
    { insmod ethertap --name="ethertap$NUM" unit="$NUM" 2>&1 || \
	{ echo "**tinc: cannot insmod ethertap$NUM" >&2 ; return 2; } ;
    } | grep -v '^Us'
    
    # configure the interface
    ip link set $TAP address $MAC
    ip link set $TAP up
    ip addr flush dev $TAP 2>&1 | grep -v -x '^Nothing to flush.'
    ip addr add $VPN brd $BRD dev $TAP
    
    # start tincd
    $TINCD --net="$1" $DEBUG || \
	{ echo "**tinc: could not start $TINCD" >&2; return 3; }

    # default interface route
    # ip route add $NET/$LEN dev $TAP

    # setup routes
    /etc/sysconfig/network-scripts/ifup-routes $TAP

    return 0
} # vpn_start


##############################################################################
# vpn_stop ()		Stops specified VPN
#
# $1 ... VPN to stop

vpn_stop () {

    vpn_load $1 || return 1
    
    # flush the routing table
    # ip route flush dev $TAP &> /dev/null
    
    # kill the tincd daemon
    PID="$TPIDS/tinc.$1.pid"
    if [ -f $PID ]; then
        $TINCD --net="$1" --kill &> /dev/null
        RET=$?
    
        if [ $RET -eq 0 ]; then
	    dly=0
	    while [ $dly -le 5 ]; do
		[ -f $PID ] || break
	        sleep 1; dly=$((dly+1))
	    done
	fi
	
	[ -f $PID ] && rm -f $PID
    fi
    
    # bring the interface down
    ip link set $TAP down &> /dev/null
    
    # remove ethertap module
    rmmod "ethertap$NUM" &> /dev/null
    
    return 0
} # vpn_stop







case "$1" in
  start)
	echo -n "Starting $DESC:"
	for net in $NETS ; do
	  echo -n " $net"
	  vpn_start $net
	  start-stop-daemon --start --quiet --pidfile /var/run/$NAME.$net.pid \
		  --exec $DAEMON -- -n $net
	done
	echo "."
	;;
  stop)
	echo -n "Stopping $DESC:"
	for net in $NETS ; do
	  echo -n " $net"
	  start-stop-daemon --stop --quiet --pidfile /var/run/$NAME.$net.pid \
		  --exec $DAEMON -- -n $net -k
	done
	echo "."
	;;
  #reload)
	#
	#	If the daemon can reload its config files on the fly
	#	for example by sending it SIGHUP, do it here.
	#
	#	If the daemon responds to changes in its config file
	#	directly anyway, make this a do-nothing entry.
	#
	# echo "Reloading $DESC configuration files."
	# start-stop-daemon --stop --signal 1 --quiet --pidfile \
	#	/var/run/$NAME.pid --exec $DAEMON
  #;;
  restart|force-reload)
	#
	#	If the "reload" option is implemented, move the "force-reload"
	#	option to the "reload" entry above. If not, "force-reload" is
	#	just the same as "restart".
	#
	echo -n "Restarting $DESC:"
	for net in $NETS ; do
	  start-stop-daemon --stop --quiet --pidfile \
		  /var/run/$NAME.$net.pid --exec $DAEMON -- -n $net -k
	  sleep 1
	  start-stop-daemon --start --quiet --pidfile \
		  /var/run/$NAME.$net.pid --exec $DAEMON -- -n $net
	  echo -n " $net"
	done
	echo "."
	;;
  *)
	N=/etc/init.d/$NAME
	# echo "Usage: $N {start|stop|restart|reload|force-reload}" >&2
	echo "Usage: $N {start|stop|restart|force-reload}" >&2
	exit 1
	;;
esac

exit 0
