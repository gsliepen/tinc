## Process this file with automake to produce Makefile.in
# $Id: Makefile.am,v 1.5 2002/04/09 15:28:45 zarq Exp $

noinst_LIBRARIES = libvpn.a

INCLUDES = @INCLUDES@ -I. -I$(top_builddir) -I$(top_srcdir)/intl

libvpn_a_SOURCES = xmalloc.c pidfile.c utils.c getopt.c getopt1.c list.c avl_tree.c dropin.c

libvpn_a_LIBADD = @LIBOBJS@ @ALLOCA@
libvpn_a_DEPENDENCIES = $(libvpn_a_LIBADD)

noinst_HEADERS = xalloc.h pidfile.h utils.h getopt.h list.h avl_tree.h dropin.h

EXTRA_DIST = README
