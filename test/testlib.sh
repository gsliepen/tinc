#!/bin/sh

# Paths to executables

tincd=../src/tincd
tinc=../src/tinc
sptps_test=../src/sptps_test
sptps_keypair=../src/sptps_keypair

# Test directories

scriptname=`basename $0`
d1=$PWD/$scriptname.1
d2=$PWD/$scriptname.2
d3=$PWD/$scriptname.3

# Default arguments for both tinc and tincd

c1="--config=$d1 --pidfile=$d1/pid"
c2="--config=$d2 --pidfile=$d2/pid"
c3="--config=$d3 --pidfile=$d3/pid"

# Arguments when running tincd

r1="--logfile=$d1/log -d5"
r2="--logfile=$d2/log -d5"
r3="--logfile=$d3/log -d5"

# Check for leftover tinc daemons

[ -f $d1/pid ] && $tinc $c1 stop
[ -f $d2/pid ] && $tinc $c2 stop
[ -f $d3/pid ] && $tinc $c3 stop

# Remove test directories

rm -rf $d1 $d2 $d3

# Exit on errors, log all commands being executed

set -ex
