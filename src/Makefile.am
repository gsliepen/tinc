## Produce this file with automake to get Makefile.in

sbin_PROGRAMS = tincd

EXTRA_DIST = linux/device.c bsd/device.c solaris/device.c cygwin/device.c mingw/device.c mingw/common.h raw_socket/device.c uml_socket/device.c

tincd_SOURCES = conf.c connection.c edge.c event.c graph.c logger.c meta.c net.c net_packet.c net_setup.c	\
	net_socket.c netutl.c node.c process.c protocol.c protocol_auth.c protocol_edge.c protocol_misc.c	\
	protocol_key.c protocol_subnet.c route.c subnet.c tincd.c

if TUNEMU
tincd_SOURCES += bsd/tunemu.c
endif

nodist_tincd_SOURCES = device.c

DEFAULT_INCLUDES =

INCLUDES = @INCLUDES@ -I$(top_builddir) -I$(top_srcdir)/lib

noinst_HEADERS = conf.h connection.h device.h edge.h event.h graph.h logger.h meta.h net.h netutl.h node.h process.h	\
	protocol.h route.h subnet.h bsd/tunemu.h

LIBS = @LIBS@

if TUNEMU
LIBS += -lpcap
endif

tincd_LDADD = \
	$(top_builddir)/lib/libvpn.a

AM_CFLAGS = -DCONFDIR=\"$(sysconfdir)\" -DLOCALSTATEDIR=\"$(localstatedir)\"

dist-hook:
	rm -f `find . -type l`
