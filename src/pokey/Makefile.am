## Produce this file with automake to get Makefile.in
# $Id: Makefile.am,v 1.2 2002/04/28 12:46:26 zarq Exp $

sbin_PROGRAMS = pokey

pokey_SOURCES = event.c graph.c	\
	interface.c logging.c meta.c net.c net_packet.c net_setup.c net_socket.c netutl.c	\
	 process.c protocol.c protocol_auth.c protocol_edge.c	\
	protocol_misc.c protocol_key.c protocol_subnet.c route.c	\
	 pokey.c

INCLUDES = @INCLUDES@ -I$(top_builddir) -I$(top_srcdir)/lib -I$(top_srcdir)/intl -I$(top_srcdir)/src -I/usr/include/gtk-1.2 -I/usr/include/glib-1.2 -I/usr/lib/glib/include -I/usr/include/libglade-1.0 -I/usr/include/gnome-1.0 -I/usr/include/gnome-xml -I/usr/include/libglade-1.0 -I/usr/include/gnome-1.0 -DNEED_GNOMESUPPORT_H -I/usr/lib/gnome-libs/include -I/usr/include/glib-1.2 -I/usr/lib/glib/include -I/usr/include/orbit-1.0 -I/usr/include/gtk-1.2 -I/usr/X11R6/include

noinst_HEADERS =  device.h event.h graph.h meta.h net.h netutl.h  process.h	\
	protocol.h route.h 

LIBS = @LIBS@ @INTLLIBS@

pokey_LDADD = \
	$(top_builddir)/lib/libtinc.a

pokey_LDFLAGS = -L/usr/X11R6/lib -lglade-gnome -lglade -lgnome -lgnomeui -L/usr/lib -lglade-gnome -lglade -L/usr/lib -lxml -lz -rdynamic -L/usr/lib -L/usr/X11R6/lib -rdynamic -lgnomeui -lart_lgpl -lgdk_imlib -lSM -lICE -lgtk -lgdk -lgmodule -ldl -lXi -lXext -lX11 -lgnome -lgnomesupport -lesd -laudiofile -lm -ldb-3 -lglib -lxml -lz -lgtk -lgdk -lXi -lXext -lX11 -lm -lglib

localedir = $(datadir)/locale

CFLAGS = @CFLAGS@ -DPKGLIBDIR=$(pkglibdir) -DCONFDIR=\"$(sysconfdir)\"	\
	-DLOCALEDIR=\"$(localedir)\" -DLOCALSTATEDIR=\"$(localstatedir)\"

lint: $(tincd_SOURCES)
	lclint -nullassign -nullret +trytorecover +posixlib -skipansiheaders -skipposixheaders +gnuextensions -I/usr/include -I/usr/lib/gcc-lib/i386-linux/2.95.2/include -I. -I/home/zarq/p/tinc/cvs/cabal/src -I.. -I.. -I/home/zarq/p/tinc/cvs/cabal/lib -I/home/zarq/p/tinc/cvs/cabal/intl -D_POSIX_SOURCE -D__ELF__ -Dunix -D__i386__ -Dlinux -DHAVE_CONFIG_H -DPKGLIBDIR=/usr/local/lib/tinc -DCONFDIR=\"/usr/local/etc\" -DLOCALEDIR=\"/usr/local/share/locale\" $^
