## Process this file with automake to produce Makefile.in
# $Id: Makefile.am,v 1.9 2002/05/02 13:11:55 zarq Exp $

noinst_LIBRARIES = libtinc.a

INCLUDES = @INCLUDES@ -I. -I$(top_builddir) -I$(top_srcdir)/intl

libtinc_a_SOURCES = xmalloc.c pidfile.c utils.c getopt.c getopt1.c	\
	list.c avl_tree.c hooks.c dropin.c edge.c conf.c netutl.c logging.c connection.c subnet.c node.c graph.c event.c

libtinc_a_LIBADD = @LIBOBJS@ @ALLOCA@
libtinc_a_DEPENDENCIES = $(libvpn_a_LIBADD)

noinst_HEADERS = xalloc.h pidfile.h utils.h getopt.h list.h avl_tree.h	\
	hooks.h dropin.h edge.h net.h conf.h netutl.h logging.h connection.h subnet.h node.h graph.h event.h

EXTRA_DIST = README
