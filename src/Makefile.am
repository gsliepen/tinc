## Produce this file with automake to get Makefile.in
# $Id: Makefile.am,v 1.4.4.14 2001/10/13 13:53:07 guus Exp $

sbin_PROGRAMS = tincd

tincd_SOURCES = conf.c connection.c device.c meta.c net.c netutl.c node.c process.c	\
	protocol.c route.c subnet.c tincd.c vertex.c

INCLUDES = @INCLUDES@ -I$(top_builddir) -I$(top_srcdir)/lib -I$(top_srcdir)/intl

noinst_HEADERS = conf.h connection.h device.h meta.h net.h netutl.h node.h process.h	\
	protocol.h route.h subnet.h vertex.h

LIBS = @LIBS@ @INTLLIBS@

tincd_LDADD = \
	$(top_builddir)/lib/libvpn.a

localedir = $(datadir)/locale

CFLAGS = @CFLAGS@ -DPKGLIBDIR=$(pkglibdir) -DCONFDIR=\"$(sysconfdir)\"	\
	-DLOCALEDIR=\"$(localedir)\" -DLOCALSTATEDIR=\"$(localstatedir)\"

lint: $(tincd_SOURCES)
	lclint -nullassign -nullret +trytorecover +posixlib -skipansiheaders -skipposixheaders +gnuextensions -I/usr/include -I/usr/lib/gcc-lib/i386-linux/2.95.2/include -I. -I/home/zarq/p/tinc/cvs/cabal/src -I.. -I.. -I/home/zarq/p/tinc/cvs/cabal/lib -I/home/zarq/p/tinc/cvs/cabal/intl -D_POSIX_SOURCE -D__ELF__ -Dunix -D__i386__ -Dlinux -DHAVE_CONFIG_H -DPKGLIBDIR=/usr/local/lib/tinc -DCONFDIR=\"/usr/local/etc\" -DLOCALEDIR=\"/usr/local/share/locale\" $^
