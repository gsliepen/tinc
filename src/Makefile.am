## Produce this file with automake to get Makefile.in
# $Id: Makefile.am,v 1.4.4.1 2000/06/06 10:24:33 zarq Exp $

sbin_PROGRAMS = tincd genauth

genauth_SOURCES = genauth.c
tincd_SOURCES = conf.c encr.c net.c netutl.c protocol.c tincd.c

INCLUDES = -I$(top_builddir) -I$(top_srcdir)/cipher -I$(top_srcdir)/lib -I$(top_srcdir)/intl

noinst_HEADERS = conf.h encr.h net.h netutl.h protocol.h

LIBS = @LIBS@ @INTLLIBS@

tincd_LDADD = $(top_builddir)/cipher/libcipher.la \
	$(top_builddir)/lib/libvpn.a

genauth_LDADD = $(top_builddir)/lib/libvpn.a

localedir = $(datadir)/locale

CFLAGS = @CFLAGS@ -DPKGLIBDIR=$(pkglibdir) -DCONFDIR=\"@sysconfdir@\" -DLOCALEDIR=\"$(localedir)\"
