## Process this file with automake to produce Makefile.in

pkglib_LTLIBRARIES = libblowfish.la

INCLUDES = -I.. -I$(srcdir)

libblowfish_la_SOURCES = bf_skey.c bf_ecb.c bf_enc.c bf_cbc.c \
bf_cfb64.c bf_ofb64.c

libblowfish_la_LDFLAGS = -version-info 0:1:0 -export-dynamic

noinst_HEADERS = bf_locl.h blowfish.h bf_pi.h

EXTRA_DIST = COPYRIGHT README