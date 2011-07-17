## Produce this file with automake to get Makefile.in

sbin_PROGRAMS = tincd tincctl

EXTRA_DIST = linux bsd solaris cygwin mingw raw_socket uml_socket openssl gcrypt

tincd_SOURCES = \
	utils.c getopt.c getopt1.c list.c splay_tree.c dropin.c fake-getaddrinfo.c fake-getnameinfo.c \
	buffer.c conf.c connection.c control.c edge.c graph.c logger.c meta.c net.c net_packet.c net_setup.c \
	net_socket.c netutl.c node.c process.c protocol.c protocol_auth.c protocol_edge.c protocol_misc.c \
	protocol_key.c protocol_subnet.c route.c subnet.c tincd.c

nodist_tincd_SOURCES = \
	device.c cipher.c crypto.c ecdh.c ecdsa.c digest.c prf.c rsa.c

tincctl_SOURCES = \
	utils.c getopt.c getopt1.c dropin.c \
	list.c tincctl.c top.c

nodist_tincctl_SOURCES = \
	ecdsagen.c rsagen.c

if TUNEMU
tincd_SOURCES += bsd/tunemu.c
endif

tincctl_LDADD = $(CURSES_LIBS)

DEFAULT_INCLUDES =

INCLUDES = @INCLUDES@ -I$(top_builddir)

noinst_HEADERS = \
	xalloc.h utils.h getopt.h list.h splay_tree.h dropin.h fake-getaddrinfo.h fake-getnameinfo.h fake-gai-errnos.h ipv6.h ipv4.h ethernet.h \
	buffer.h conf.h connection.h control.h control_common.h device.h edge.h graph.h logger.h meta.h net.h netutl.h node.h process.h \
	protocol.h route.h subnet.h tincctl.h top.h bsd/tunemu.h

nodist_noinst_HEADERS = \
	cipher.h crypto.h ecdh.h ecdsa.h digest.h prf.h rsa.h ecdsagen.h rsagen.h

LIBS = @LIBS@ @LIBGCRYPT_LIBS@

if TUNEMU
LIBS += -lpcap
endif

AM_CFLAGS = -DCONFDIR=\"$(sysconfdir)\" -DLOCALSTATEDIR=\"$(localstatedir)\" -DSBINDIR=\"$(sbindir)\"

dist-hook:
	rm -f `find . -type l`
