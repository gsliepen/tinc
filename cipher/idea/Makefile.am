## Process this file with automake to produce Makefile.in

pkglib_LTLIBRARIES = libidea.la

INCLUDES = -I.. -I$(srcdir)

libidea_la_SOURCES = i_skey.c i_ecb.c i_cbc.c \
i_cfb64.c i_ofb64.c

libidea_la_LDFLAGS = -version-info 0:1:0 -export-dynamic

noinst_HEADERS = idea_lcl.h idea.h

EXTRA_DIST = COPYRIGHT
