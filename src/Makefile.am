## Produce this file with automake to get Makefile.in

sbin_PROGRAMS = tincd tinc sptps_test

EXTRA_DIST = linux bsd solaris cygwin mingw openssl gcrypt

tincd_SOURCES = \
	buffer.c \
	conf.c \
	connection.c \
	control.c \
	dropin.c \
	dummy_device.c \
	edge.c \
	event.c \
	fake-getaddrinfo.c \
	fake-getnameinfo.c \
	getopt.c \
	getopt1.c \
	graph.c \
	hash.c \
	list.c \
	logger.c \
	meta.c \
	multicast_device.c \
	names.c \
	net.c \
	net_packet.c \
	net_setup.c \
	net_socket.c \
	netutl.c \
	node.c \
	process.c \
	protocol.c \
	protocol_auth.c \
	protocol_edge.c \
	protocol_key.c \
	protocol_misc.c \
	protocol_subnet.c \
	raw_socket_device.c \
	route.c \
	splay_tree.c \
	sptps.c \
	subnet.c \
	subnet_parse.c \
	tincd.c \
	utils.c

tinc_SOURCES = \
	dropin.c \
	getopt.c \
	getopt1.c \
	info.c \
	invitation.c \
	list.c \
	names.c \
	netutl.c \
	sptps.c \
	subnet_parse.c \
	tincctl.c \
	top.c \
	utils.c

sptps_test_SOURCES = \
	logger.c \
	sptps.c \
	sptps_test.c \
	utils.c

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
	openssl/digest.c \
	openssl/ecdh.c \
	openssl/ecdsa.c \
	openssl/prf.c \
	openssl/rsa.c
tinc_SOURCES += \
	openssl/cipher.c \
	openssl/crypto.c \
	openssl/digest.c \
	openssl/ecdh.c \
	openssl/ecdsa.c \
	openssl/ecdsagen.c \
	openssl/prf.c \
	openssl/rsa.c \
	openssl/rsagen.c
sptps_test_SOURCES += \
	openssl/cipher.c \
	openssl/crypto.c \
	openssl/digest.c \
	openssl/ecdh.c \
	openssl/ecdsa.c \
	openssl/prf.c
endif

if GCRYPT
tincd_SOURCES += \
	gcrypt/cipher.c \
	gcrypt/crypto.c \
	gcrypt/digest.c \
	gcrypt/ecdh.c \
	gcrypt/ecdsa.c \
	gcrypt/prf.c \
	gcrypt/rsa.c
tinc_SOURCES += \
	gcrypt/cipher.c \
	gcrypt/crypto.c \
	gcrypt/digest.c \
	gcrypt/ecdh.c \
	gcrypt/ecdsa.c \
	gcrypt/ecdsagen.c \
	gcrypt/prf.c \
	gcrypt/rsa.c \
	gcrypt/rsagen.c
sptps_test_SOURCES += \
	gcrypt/cipher.c \
	gcrypt/crypto.c \
	gcrypt/digest.c \
	gcrypt/ecdh.c \
	gcrypt/ecdsa.c \
	gcrypt/prf.c
endif

tinc_LDADD = $(READLINE_LIBS) $(CURSES_LIBS)

noinst_HEADERS = \
	buffer.h \
	cipher.h \
	conf.h \
	connection.h \
	control.h \
	control_common.h \
	crypto.h \
	device.h \
	digest.h \
	dropin.h \
	ecdh.h \
	ecdsa.h \
	ecdsagen.h \
	edge.h \
	ethernet.h \
	event.h \
	fake-gai-errnos.h \
	fake-getaddrinfo.h \
	fake-getnameinfo.h \
	getopt.h \
	graph.h \
	hash.h \
	have.h \
	info.h \
	ipv4.h \
	ipv6.h \
	list.h \
	logger.h \
	meta.h \
	names.h \
	net.h \
	netutl.h \
	node.h \
	prf.h \
	process.h \
	protocol.h \
	route.h \
	rsa.h \
	rsagen.h
	splay_tree.h \
	sptps.h \
	subnet.h \
	system.h \
	tincctl.h \
	top.h \
	utils.h \
	xalloc.h

LIBS = @LIBS@ @LIBGCRYPT_LIBS@

if TUNEMU
LIBS += -lpcap
endif

AM_CFLAGS = -DCONFDIR=\"$(sysconfdir)\" -DLOCALSTATEDIR=\"$(localstatedir)\" -DSBINDIR=\"$(sbindir)\"

dist-hook:
	rm -f `find . -type l`
