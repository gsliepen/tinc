## Process this file with automake to produce Makefile.in
# $Id$

noinst_LIBRARIES = libvpn.a

INCLUDES = @INCLUDES@ -I. -I$(top_builddir)

libvpn_a_SOURCES = xmalloc.c utils.c getopt.c getopt1.c list.c splay_tree.c dropin.c fake-getaddrinfo.c fake-getnameinfo.c

libvpn_a_LIBADD = @LIBOBJS@ @ALLOCA@
libvpn_a_DEPENDENCIES = $(libvpn_a_LIBADD)

noinst_HEADERS = xalloc.h utils.h getopt.h list.h splay_tree.h dropin.h fake-getaddrinfo.h fake-getnameinfo.h fake-gai-errnos.h gettext.h ipv6.h ipv4.h ethernet.h

EXTRA_DIST = 
