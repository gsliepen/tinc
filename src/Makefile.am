## Produce this file with automake to get Makefile.in
# $Id: Makefile.am,v 1.4.4.5 2000/11/02 21:26:51 zarq Exp $

sbin_PROGRAMS = tincd

tincd_SOURCES = conf.c connlist.c meta.c net.c netutl.c protocol.c subnet.c tincd.c

INCLUDES = -I$(top_builddir) -I$(top_srcdir)/lib -I$(top_srcdir)/intl

noinst_HEADERS = conf.h connlist.h meta.h net.h netutl.h protocol.h subnet.h

LIBS = @LIBS@ @INTLLIBS@

tincd_LDADD = \
	$(top_builddir)/lib/libvpn.a

localedir = $(datadir)/locale

CFLAGS = @CFLAGS@ -DPKGLIBDIR=$(pkglibdir) -DCONFDIR=\"@sysconfdir@\" -DLOCALEDIR=\"$(localedir)\"
