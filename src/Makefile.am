## Produce this file with automake to get Makefile.in

sbin_PROGRAMS = tincd

tincd_SOURCES = \
	have.h \
	system.h \
	avl_tree.c avl_tree.h \
	conf.c conf.h \
	connection.c connection.h \
	device.h \
	dropin.c dropin.h \
	dummy_device.c \
	edge.c edge.h \
	ethernet.h \
	event.c event.h \
	fake-gai-errnos.h \
	fake-getaddrinfo.c fake-getaddrinfo.h \
	fake-getnameinfo.c fake-getnameinfo.h \
	graph.c graph.h \
	ipv4.h \
	ipv6.h \
	list.c list.h \
	logger.c logger.h \
	meta.c meta.h \
	multicast_device.c \
	net.c net.h \
	net_packet.c \
	net_setup.c \
	net_socket.c \
	netutl.c netutl.h \
	node.c node.h \
	pidfile.c pidfile.h \
	process.c process.h \
	protocol.c protocol.h \
	protocol_auth.c \
	protocol_edge.c \
	protocol_misc.c \
	protocol_key.c \
	protocol_subnet.c \
	proxy.c proxy.h \
	raw_socket_device.c \
	route.c route.h \
	subnet.c subnet.h \
	tincd.c \
	utils.c utils.h \
	xalloc.h \
	xmalloc.c

if !GETOPT
tincd_SOURCES += \
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

if CYGWIN
tincd_SOURCES += cygwin/device.c
endif

if UML
tincd_SOURCES += uml_device.c
endif

if VDE
tincd_SOURCES += vde_device.c
endif

if TUNEMU
LIBS += -lpcap
endif

AM_CPPFLAGS = -DCONFDIR=\"$(sysconfdir)\" -DLOCALSTATEDIR=\"$(localstatedir)\"
