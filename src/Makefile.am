## Produce this file with automake to get Makefile.in
# $Id: Makefile.am,v 1.10 2002/04/28 12:46:26 zarq Exp $

SUBDIRS = pokey

sbin_PROGRAMS = tincd

EXTRA_DIST = linux/device.c freebsd/device.c openbsd/device.c solaris/device.c

tincd_SOURCES = read_conf.c device.c event.c graph.c meta.c net_packet.c net_setup.c	\
	net_socket.c process.c protocol.c protocol_auth.c protocol_edge.c protocol_misc.c	\
	protocol_key.c protocol_subnet.c route.c tincd.c net.c

INCLUDES = @INCLUDES@ -I$(top_builddir) -I$(top_srcdir)/lib -I$(top_srcdir)/intl

noinst_HEADERS = read_conf.h  device.h event.h graph.h  meta.h process.h	\
	protocol.h route.h 

LIBS = @LIBS@ @INTLLIBS@

tincd_LDADD = \
	$(top_builddir)/lib/libtinc.a -lgcrypt

localedir = $(datadir)/locale

CFLAGS = @CFLAGS@ -DPKGLIBDIR=$(pkglibdir) -DCONFDIR=\"$(sysconfdir)\"	\
	-DLOCALEDIR=\"$(localedir)\" -DLOCALSTATEDIR=\"$(localstatedir)\"

dist-hook:
	rm -f `find . -type l`

lint: $(tincd_SOURCES)
	lclint -nullassign -nullret +trytorecover +posixlib -skipansiheaders -skipposixheaders +gnuextensions -I/usr/include -I/usr/lib/gcc-lib/i386-linux/2.95.2/include -I. -I/home/zarq/p/tinc/cvs/cabal/src -I.. -I.. -I/home/zarq/p/tinc/cvs/cabal/lib -I/home/zarq/p/tinc/cvs/cabal/intl -D_POSIX_SOURCE -D__ELF__ -Dunix -D__i386__ -Dlinux -DHAVE_CONFIG_H -DPKGLIBDIR=/usr/local/lib/tinc -DCONFDIR=\"/usr/local/etc\" -DLOCALEDIR=\"/usr/local/share/locale\" $^
