## Process this file with automake to produce Makefile.in

noinst_LIBRARIES = libvpn.a

INCLUDES = -I. -I$(top_builddir)

libvpn_a_SOURCES = xmalloc.c pidfile.c utils.c getopt.c getopt1.c

libvpn_a_LIBADD = @LIBOBJS@ @ALLOCA@
libvpn_a_DEPENDENCIES = $(libvpn_a_LIBADD)

noinst_HEADERS = xalloc.h pidfile.h utils.h getopt.h

EXTRA_DIST = README