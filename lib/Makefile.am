## Process this file with automake to produce Makefile.in
# $Id: Makefile.am,v 1.2.4.6 2001/01/05 23:50:55 guus Exp $

noinst_LIBRARIES = libvpn.a

INCLUDES = -I. -I$(top_builddir) -I$(top_srcdir)/intl

libvpn_a_SOURCES = xmalloc.c pidfile.c utils.c getopt.c getopt1.c list.c avl_tree.c dropin.c

libvpn_a_LIBADD = @LIBOBJS@ @ALLOCA@
libvpn_a_DEPENDENCIES = $(libvpn_a_LIBADD)

noinst_HEADERS = xalloc.h pidfile.h utils.h getopt.h list.h avl_tree.h dropin.h

EXTRA_DIST = README
