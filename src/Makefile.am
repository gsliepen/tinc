## Produce this file with automake to get Makefile.in

sbin_PROGRAMS = tincd tinc sptps_test

EXTRA_DIST = linux bsd solaris cygwin mingw openssl gcrypt

tincd_SOURCES = \
	utils.c getopt.c getopt1.c list.c splay_tree.c dropin.c fake-getaddrinfo.c fake-getnameinfo.c hash.c \
	buffer.c conf.c connection.c control.c edge.c graph.c logger.c meta.c net.c net_packet.c net_setup.c \
	net_socket.c netutl.c node.c process.c protocol.c protocol_auth.c protocol_edge.c protocol_misc.c \
	protocol_key.c protocol_subnet.c route.c sptps.c subnet.c subnet_parse.c event.c tincd.c \
	dummy_device.c raw_socket_device.c multicast_device.c names.c

tinc_SOURCES = \
	utils.c getopt.c getopt1.c dropin.c \
	info.c list.c subnet_parse.c tincctl.c top.c names.c

sptps_test_SOURCES = \
	logger.c sptps.c sptps_test.c utils.c

## Conditionally compile device drivers
	
if LINUX
tincd_SOURCES += linux/device.c
endif

if BSD
tincd_SOURCES += bsd/device.c
if TUNEMU
tincd_SOURCES += bsd/tunemu.c
endif
endif

if SOLARIS
tincd_SOURCES += solaris/device.c
endif

if MINGW
tincd_SOURCES += mingw/device.c
endif

if CYGWIN
tincd_SOURCES += cygwin/device.c
endif

if UML
tincd_SOURCES += uml_device.c
endif

if VDE
tincd_SOURCES += vde_device.c
endif

if OPENSSL
tincd_SOURCES += \
	openssl/cipher.c \
	openssl/crypto.c \
	openssl/ecdh.c \
	openssl/ecdsa.c \
	openssl/digest.c \
	openssl/prf.c \
	openssl/rsa.c
tinc_SOURCES += \
	openssl/ecdsa.c \
	openssl/ecdsagen.c \
	openssl/rsa.c \
	openssl/rsagen.c
sptps_test_SOURCES += \
	openssl/cipher.c \
	openssl/crypto.c \
	openssl/ecdh.c \
	openssl/ecdsa.c \
	openssl/digest.c \
	openssl/prf.c
endif

if GCRYPT
tincd_SOURCES += \
	gcrypt/cipher.c \
	gcrypt/crypto.c \
	gcrypt/ecdh.c \
	gcrypt/ecdsa.c \
	gcrypt/digest.c \
	gcrypt/prf.c \
	gcrypt/rsa.c
tinc_SOURCES += \
	gcrypt/ecdsa.c \
	gcrypt/ecdsagen.c \
	gcrypt/rsa.c \
	gcrypt/rsagen.c
sptps_test_SOURCES += \
	gcrypt/cipher.c \
	gcrypt/crypto.c \
	gcrypt/ecdh.c \
	gcrypt/ecdsa.c \
	gcrypt/digest.c \
	gcrypt/prf.c
endif

tinc_LDADD = $(READLINE_LIBS) $(CURSES_LIBS)

DEFAULT_INCLUDES =

INCLUDES = @INCLUDES@

noinst_HEADERS = \
	xalloc.h utils.h getopt.h list.h splay_tree.h dropin.h fake-getaddrinfo.h fake-getnameinfo.h fake-gai-errnos.h ipv6.h ipv4.h ethernet.h \
	buffer.h conf.h connection.h control.h control_common.h device.h edge.h graph.h info.h logger.h meta.h net.h netutl.h node.h process.h \
	protocol.h route.h subnet.h sptps.h tincctl.h top.h hash.h event.h names.h have.h system.h

LIBS = @LIBS@ @LIBGCRYPT_LIBS@

if TUNEMU
LIBS += -lpcap
endif

AM_CFLAGS = -DCONFDIR=\"$(sysconfdir)\" -DLOCALSTATEDIR=\"$(localstatedir)\" -DSBINDIR=\"$(sbindir)\"

dist-hook:
	rm -f `find . -type l`
