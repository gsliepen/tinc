## Process this file with automake to produce Makefile.in
# $Id: Makefile.am,v 1.2.4.4 2000/11/24 23:12:58 guus Exp $

noinst_LIBRARIES = libvpn.a

INCLUDES = -I. -I$(top_builddir) -I$(top_srcdir)/intl

libvpn_a_SOURCES = xmalloc.c pidfile.c utils.c getopt.c getopt1.c list.c rbl.c daemon.c

libvpn_a_LIBADD = @LIBOBJS@ @ALLOCA@
libvpn_a_DEPENDENCIES = $(libvpn_a_LIBADD)

noinst_HEADERS = xalloc.h pidfile.h utils.h getopt.h list.h rbl.h daemon.h

EXTRA_DIST = README
