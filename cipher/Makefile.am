## Process this file with automake to get Makefile.in

SUBDIRS = blowfish

noinst_LTLIBRARIES = libcipher.la

INCLUDES = -I. -I$(top_builddir) -I$(top_srcdir)/src

libcipher_la_SOURCES = cipher.c

libcipher_la_LDFLAGS =

noinst_HEADERS = cipher.h

CFLAGS = @CFLAGS@ -DPKGLIBDIR="\"$(pkglibdir)/\""
