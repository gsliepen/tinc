## Produce this file with automake to get Makefile.in

sbin_PROGRAMS = tincd tinc
check_PROGRAMS = sptps_test sptps_keypair
EXTRA_PROGRAMS = $(check_PROGRAMS)

CLEANFILES = version_git.h

.PHONY: extra
extra: $(EXTRA_PROGRAMS)

.PHONY: version-stamp
version-stamp:

version_git.h: version-stamp
	$(AM_V_GEN)echo >$@
	@-(cd $(srcdir) && git describe 2>/dev/null >/dev/null) && echo '#define GIT_DESCRIPTION "'`(cd $(srcdir) && git describe) | sed 's/release-//'`'"' >$@ ||:
${srcdir}/version.c: version_git.h

## Now a hack to appease some versions of BSD make that don't understand that "./foo" is the same as "foo".
if BSD
version.c: ${srcdir}/version.c
endif

if LINUX
EXTRA_PROGRAMS += sptps_speed
endif

ed25519_SOURCES = \
	ed25519/ed25519.h \
	ed25519/fe.c ed25519/fe.h \
	ed25519/fixedint.h \
	ed25519/ge.c ed25519/ge.h \
	ed25519/key_exchange.c \
	ed25519/keypair.c \
	ed25519/precomp_data.h \
	ed25519/sc.c ed25519/sc.h \
	ed25519/sha512.c ed25519/sha512.h \
	ed25519/sign.c \
	ed25519/verify.c

chacha_poly1305_SOURCES = \
	chacha-poly1305/chacha.c chacha-poly1305/chacha.h \
	chacha-poly1305/chacha-poly1305.c chacha-poly1305/chacha-poly1305.h \
	chacha-poly1305/poly1305.c chacha-poly1305/poly1305.h

if CONFIGURE_LZ4_BUILTIN
lz4_SOURCES = lib/lz4/lz4.c lib/lz4/lz4.h
else
lz4_SOURCES =
endif

tincd_SOURCES = \
	address_cache.c address_cache.h \
	autoconnect.c autoconnect.h \
	buffer.c buffer.h \
	cipher.h \
	compression.h \
	conf.c conf.h \
	conf_net.c conf_net.h \
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
	fd_device.c \
	graph.c graph.h \
	hash.h \
	keys.c keys.h \
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
	xalloc.h \
	xoshiro.c \
	version.c version.h \
	ed25519/ecdh.c \
	ed25519/ecdsa.c \
	$(ed25519_SOURCES) \
	$(chacha_poly1305_SOURCES) \
	$(lz4_SOURCES)

tinc_SOURCES = \
	dropin.c dropin.h \
	fsck.c fsck.h \
	ifconfig.c ifconfig.h \
	info.c info.h \
	invitation.c invitation.h \
	conf.c conf.h \
	keys.c keys.h \
	splay_tree.c splay_tree.h \
	list.c list.h \
	names.c names.h \
	netutl.c netutl.h \
	script.c script.h \
	sptps.c sptps.h \
	subnet_parse.c subnet.h \
	tincctl.c tincctl.h \
	top.c top.h \
	utils.c utils.h \
	version.c version.h \
	ed25519/ecdh.c \
	ed25519/ecdsa.c \
	ed25519/ecdsagen.c \
	xoshiro.c \
	$(ed25519_SOURCES) \
	$(chacha_poly1305_SOURCES)

sptps_test_SOURCES = \
	logger.c logger.h \
	sptps.c sptps.h \
	sptps_test.c \
	utils.c utils.h \
	xoshiro.c \
	ed25519/ecdh.c \
	ed25519/ecdsa.c \
	$(ed25519_SOURCES) \
	$(chacha_poly1305_SOURCES)

sptps_keypair_SOURCES = \
	sptps_keypair.c \
	utils.c utils.h \
	ed25519/ecdsagen.c \
	$(ed25519_SOURCES)

sptps_speed_SOURCES = \
	logger.c logger.h \
	sptps.c sptps.h \
	sptps_speed.c \
	utils.c utils.h \
	ed25519/ecdh.c \
	ed25519/ecdsa.c \
	ed25519/ecdsagen.c \
	$(ed25519_SOURCES) \
	$(chacha_poly1305_SOURCES)

## Conditionally compile device drivers

if !GETOPT
tincd_SOURCES += \
	getopt.c getopt.h \
	getopt1.c
tinc_SOURCES += \
	getopt.c getopt.h \
	getopt1.c
sptps_test_SOURCES += \
	getopt.c getopt.h \
	getopt1.c
sptps_keypair_SOURCES += \
	getopt.c getopt.h \
	getopt1.c
endif

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

if UML
tincd_SOURCES += uml_device.c
endif

if VDE
tincd_SOURCES += vde_device.c
endif

if OPENSSL
tincd_SOURCES += \
	openssl/cipher.c openssl/cipher.h \
	openssl/crypto.c \
	openssl/digest.c openssl/digest.h \
	openssl/prf.c \
	openssl/rsa.c \
	openssl/log.c openssl/log.h
tinc_SOURCES += \
	openssl/cipher.c openssl/cipher.h \
	openssl/crypto.c \
	openssl/digest.c openssl/digest.h \
	openssl/prf.c \
	openssl/rsa.c \
	openssl/rsagen.c \
	openssl/log.c openssl/log.h
sptps_test_SOURCES += \
	openssl/crypto.c \
	openssl/digest.c openssl/digest.h \
	openssl/prf.c \
	openssl/log.c openssl/log.h
sptps_keypair_SOURCES += \
	openssl/crypto.c
sptps_speed_SOURCES += \
	openssl/crypto.c \
	openssl/digest.c openssl/digest.h \
	openssl/prf.c \
	openssl/log.c openssl/log.h
else
if GCRYPT
tincd_SOURCES += \
	gcrypt/cipher.c gcrypt/cipher.h \
	gcrypt/crypto.c \
	gcrypt/digest.c gcrypt/digest.h \
	gcrypt/pem.c gcrypt/pem.h \
	gcrypt/prf.c \
	gcrypt/rsa.c gcrypt/rsa.h
tinc_SOURCES += \
	gcrypt/cipher.c gcrypt/cipher.h \
	gcrypt/crypto.c \
	gcrypt/digest.c gcrypt/digest.h \
	gcrypt/pem.c gcrypt/pem.h \
	gcrypt/prf.c \
	gcrypt/rsa.c gcrypt/rsa.h \
	gcrypt/rsagen.c
sptps_test_SOURCES += \
	gcrypt/cipher.c gcrypt/cipher.h \
	gcrypt/crypto.c \
	gcrypt/digest.c gcrypt/digest.h \
	gcrypt/prf.c
sptps_keypair_SOURCES += \
	gcrypt/crypto.c
sptps_speed_SOURCES += \
	gcrypt/crypto.c \
	gcrypt/digest.c gcrypt/digest.h \
	gcrypt/prf.c
else
tincd_SOURCES += \
	nolegacy/crypto.c \
	nolegacy/prf.c
tinc_SOURCES += \
	nolegacy/crypto.c \
	nolegacy/prf.c
sptps_test_SOURCES += \
	nolegacy/crypto.c \
	nolegacy/prf.c
sptps_keypair_SOURCES += \
	nolegacy/crypto.c
sptps_speed_SOURCES += \
	nolegacy/crypto.c \
	nolegacy/prf.c
endif
endif

if WITH_LEGACY_PROTOCOL
tinc_SOURCES        += digest.c
tincd_SOURCES       += digest.c cipher.c
sptps_test_SOURCES  += digest.c
sptps_speed_SOURCES += digest.c
endif

if MINIUPNPC
tincd_SOURCES += upnp.h upnp.c
tincd_LDADD = $(MINIUPNPC_LIBS)
tincd_LDFLAGS = -pthread
endif

if MINGW
sptps_test_LDFLAGS = -pthread
endif

tinc_LDADD = $(READLINE_LIBS) $(CURSES_LIBS)
sptps_speed_LDADD = -lrt

LIBS = @LIBS@ -lm $(CODE_COVERAGE_LIBS)

if TUNEMU
LIBS += -lpcap
endif

AM_CFLAGS = -DCONFDIR=\"$(sysconfdir)\" -DRUNSTATEDIR=\"$(runstatedir)\" -DLOCALSTATEDIR=\"$(localstatedir)\" -DSBINDIR=\"$(sbindir)\" -iquote. $(CODE_COVERAGE_CFLAGS)
AM_CPPFLAGS = $(CODE_COVERAGE_CPPFLAGS)
