## Process this file with automake to produce Makefile.in
# $Id: Makefile.am,v 1.6 2002/04/13 11:23:19 zarq Exp $

noinst_LIBRARIES = libtinc.a

INCLUDES = @INCLUDES@ -I. -I$(top_builddir) -I$(top_srcdir)/intl

libtinc_a_SOURCES = xmalloc.c pidfile.c utils.c getopt.c getopt1.c list.c avl_tree.c dropin.c

libtinc_a_LIBADD = @LIBOBJS@ @ALLOCA@
libtinc_a_DEPENDENCIES = $(libvpn_a_LIBADD)

noinst_HEADERS = xalloc.h pidfile.h utils.h getopt.h list.h avl_tree.h dropin.h

EXTRA_DIST = README
