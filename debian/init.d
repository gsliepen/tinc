#! /bin/sh
#
# System startup script for tinc
# $Id: init.d,v 1.14.2.4 2000/12/05 09:03:41 zarq Exp $
#
# Based on Lubomir Bulej's Redhat init script.
#
# Create a file $NETSFILE (/etc/tinc/nets.boot), and put all the names of
# the networks in there.  These names must be valid directory names under
# $TCONF (/etc/tinc).  Lines starting with a # will be ignored in this
# file.
#

DAEMON="/usr/sbin/tincd"
NAME="tinc"
DESC="tinc daemons"
TCONF="/etc/tinc"
EXTRA=""
NETSFILE="$TCONF/nets.boot"
NETS=""

test -f $DAEMON || exit 0

find_nets () {
  if [ ! -f $NETSFILE ] ; then
    echo "Please create $NETSFILE."
    exit 0
  fi
  NETS="`egrep '^[ ]*[a-zA-Z0-9_]+[ ]*$' $NETSFILE`"
}

case "$1" in
  start)
    find_nets
    echo -n "Starting $DESC:"
    for n in $NETS ; do
      echo -n " $n"
      $DAEMON -n $n $EXTRA
    done
    echo "."
  ;;
  stop)
    find_nets
    echo -n "Stopping $DESC:"
    for n in $NETS ; do
      echo -n " $n"
      $DAEMON -n $n $EXTRA -k
    done
    echo "."
  ;;
  restart|force-reload)
    find_nets
    echo -n "Restarting $DESC:"
    for n in $NETS ; do
      echo -n " $n"
      $DAEMON -n $n $EXTRA -k
      sleep 1
      $DAEMON -n $n $EXTRA
    done
    echo "."
  ;;
  *)
    echo "Usage: /etc/init.d/$NAME {start|stop|restart|force-reload}"
    exit 1
  ;;
esac
