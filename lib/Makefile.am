## Process this file with automake to produce Makefile.in

noinst_LIBRARIES = libvpn.a

INCLUDES = @INCLUDES@ -I. -I$(top_builddir)

libvpn_a_SOURCES = xmalloc.c pidfile.c utils.c getopt.c getopt1.c list.c avl_tree.c dropin.c fake-getaddrinfo.c fake-getnameinfo.c

libvpn_a_LIBADD = @LIBOBJS@ @ALLOCA@
libvpn_a_DEPENDENCIES = $(libvpn_a_LIBADD)

noinst_HEADERS = xalloc.h pidfile.h utils.h getopt.h list.h avl_tree.h dropin.h fake-getaddrinfo.h fake-getnameinfo.h fake-gai-errnos.h ipv6.h ipv4.h ethernet.h

EXTRA_DIST = 
