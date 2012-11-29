## Produce this file with automake to get Makefile.in

sbin_PROGRAMS = tincd tincctl sptps_test

EXTRA_DIST = linux bsd solaris cygwin mingw openssl gcrypt

tincd_SOURCES = \
	utils.c getopt.c getopt1.c list.c splay_tree.c dropin.c fake-getaddrinfo.c fake-getnameinfo.c hash.c \
	buffer.c conf.c connection.c control.c edge.c graph.c logger.c meta.c net.c net_packet.c net_setup.c \
	net_socket.c netutl.c node.c process.c protocol.c protocol_auth.c protocol_edge.c protocol_misc.c \
	protocol_key.c protocol_subnet.c route.c sptps.c subnet.c subnet_parse.c event.c tincd.c \
	dummy_device.c raw_socket_device.c multicast_device.c
	
if UML
tincd_SOURCES += uml_device.c
endif

if VDE
tincd_SOURCES += vde_device.c
endif

nodist_tincd_SOURCES = \
	device.c cipher.c crypto.c ecdh.c ecdsa.c digest.c prf.c rsa.c

tincctl_SOURCES = \
	utils.c getopt.c getopt1.c dropin.c \
	info.c list.c subnet_parse.c tincctl.c top.c

nodist_tincctl_SOURCES = \
	ecdsagen.c rsagen.c

sptps_test_SOURCES = \
	logger.c cipher.c crypto.c ecdh.c ecdsa.c digest.c prf.c \
	sptps.c sptps_test.c utils.c

if TUNEMU
tincd_SOURCES += bsd/tunemu.c
endif

tincctl_LDADD = $(READLINE_LIBS) $(CURSES_LIBS)

DEFAULT_INCLUDES =

INCLUDES = @INCLUDES@ -I$(top_builddir)

noinst_HEADERS = \
	xalloc.h utils.h getopt.h list.h splay_tree.h dropin.h fake-getaddrinfo.h fake-getnameinfo.h fake-gai-errnos.h ipv6.h ipv4.h ethernet.h \
	buffer.h conf.h connection.h control.h control_common.h device.h edge.h graph.h info.h logger.h meta.h net.h netutl.h node.h process.h \
	protocol.h route.h subnet.h sptps.h tincctl.h top.h bsd/tunemu.h hash.h event.h

nodist_noinst_HEADERS = \
	cipher.h crypto.h ecdh.h ecdsa.h digest.h prf.h rsa.h ecdsagen.h rsagen.h

LIBS = @LIBS@ @LIBGCRYPT_LIBS@

if TUNEMU
LIBS += -lpcap
endif

AM_CFLAGS = -DCONFDIR=\"$(sysconfdir)\" -DLOCALSTATEDIR=\"$(localstatedir)\" -DSBINDIR=\"$(sbindir)\"

dist-hook:
	rm -f `find . -type l`
