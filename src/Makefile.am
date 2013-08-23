## Produce this file with automake to get Makefile.in

sbin_PROGRAMS = tincd tinc sptps_test

DEFAULT_INCLUDES =

tincd_SOURCES = \
	buffer.c buffer.h \
	cipher.h \
	conf.c conf.h \
	connection.c connection.h \
	control.c control.h \
	control_common.h \
	crypto.h \
	device.h \
	digest.h \
	dropin.c dropin.h \
	dummy_device.c \
	ecdh.h \
	ecdsa.h \
	ecdsagen.h \
	edge.c edge.h \
	ethernet.h \
	event.c event.h \
	fake-gai-errnos.h \
	fake-getaddrinfo.c fake-getaddrinfo.h \
	fake-getnameinfo.c fake-getnameinfo.h \
	getopt.c getopt.h \
	getopt1.c \
	graph.c graph.h \
	hash.c hash.h \
	have.h \
	ipv4.h \
	ipv6.h \
	list.c list.h \
	logger.c logger.h \
	meta.c meta.h \
	multicast_device.c \
	names.c names.h \
	net.c net.h \
	net_packet.c \
	net_setup.c \
	net_socket.c \
	netutl.c netutl.h \
	node.c node.h \
	prf.h \
	process.c process.h \
	protocol.c protocol.h \
	protocol_auth.c \
	protocol_edge.c \
	protocol_key.c \
	protocol_misc.c \
	protocol_subnet.c \
	raw_socket_device.c \
	route.c route.h \
	rsa.h \
	rsagen.h \
	script.c script.h \
	splay_tree.c splay_tree.h \
	sptps.c sptps.h \
	subnet.c subnet.h \
	subnet_parse.c \
	system.h \
	tincd.c \
	utils.c utils.h \
	xalloc.h

tinc_SOURCES = \
	dropin.c dropin.h \
	getopt.c getopt.h \
	getopt1.c \
	info.c info.h \
	invitation.c invitation.h \
	list.c list.h \
	names.c names.h \
	netutl.c netutl.h \
	script.c script.h \
	sptps.c sptps.h \
	subnet_parse.c subnet.h \
	tincctl.c tincctl.h \
	top.c top.h \
	utils.c utils.h

sptps_test_SOURCES = \
	logger.c logger.h \
	sptps.c sptps.h \
	sptps_test.c \
	utils.c utils.h

## Conditionally compile device drivers
	
if LINUX
tincd_SOURCES += linux/device.c
endif

if BSD
tincd_SOURCES += bsd/device.c
if TUNEMU
tincd_SOURCES += bsd/tunemu.c bsd/tunemu.h
endif
endif

if SOLARIS
tincd_SOURCES += solaris/device.c
endif

if MINGW
tincd_SOURCES += mingw/device.c mingw/common.h
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
	openssl/digest.c openssl/digest.h \
	openssl/ecdh.c \
	openssl/ecdsa.c \
	openssl/prf.c \
	openssl/rsa.c
tinc_SOURCES += \
	openssl/cipher.c \
	openssl/crypto.c \
	openssl/digest.c openssl/digest.h \
	openssl/ecdh.c \
	openssl/ecdsa.c \
	openssl/ecdsagen.c \
	openssl/prf.c \
	openssl/rsa.c \
	openssl/rsagen.c
sptps_test_SOURCES += \
	openssl/cipher.c \
	openssl/crypto.c \
	openssl/digest.c openssl/digest.h \
	openssl/ecdh.c \
	openssl/ecdsa.c \
	openssl/prf.c
endif

if GCRYPT
tincd_SOURCES += \
	gcrypt/cipher.c \
	gcrypt/crypto.c \
	gcrypt/digest.c gcrypt/digest.h \
	gcrypt/ecdh.c \
	gcrypt/ecdsa.c \
	gcrypt/prf.c \
	gcrypt/rsa.c
tinc_SOURCES += \
	gcrypt/cipher.c \
	gcrypt/crypto.c \
	gcrypt/digest.c gcrypt/digest.h \
	gcrypt/ecdh.c \
	gcrypt/ecdsa.c \
	gcrypt/ecdsagen.c \
	gcrypt/prf.c \
	gcrypt/rsa.c \
	gcrypt/rsagen.c
sptps_test_SOURCES += \
	gcrypt/cipher.c \
	gcrypt/crypto.c \
	gcrypt/digest.c gcrypt/digest.h \
	gcrypt/ecdh.c \
	gcrypt/ecdsa.c \
	gcrypt/prf.c
endif

tinc_LDADD = $(READLINE_LIBS) $(CURSES_LIBS)

LIBS = @LIBS@ @LIBGCRYPT_LIBS@

if TUNEMU
LIBS += -lpcap
endif

AM_CFLAGS = -DCONFDIR=\"$(sysconfdir)\" -DLOCALSTATEDIR=\"$(localstatedir)\" -DSBINDIR=\"$(sbindir)\"
