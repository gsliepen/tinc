## Produce this file with automake to get Makefile.in

sbin_PROGRAMS = tincd genauth

genauth_SOURCES = genauth.c
tincd_SOURCES = conf.c encr.c net.c netutl.c protocol.c tincd.c

INCLUDES = -I$(top_builddir) -I$(top_srcdir)/cipher -I$(top_srcdir)/lib

noinst_HEADERS = conf.h encr.h net.h netutl.h protocol.h

LIBS = @LIBS@

tincd_LDADD = $(top_builddir)/cipher/libcipher.la \
	$(top_builddir)/lib/libvpn.a -ldl

genauth_LDADD = $(top_builddir)/lib/libvpn.a

CFLAGS += -DPKGLIBDIR=$(pkglibdir) -DCONFDIR=\"@sysconfdir@\"
