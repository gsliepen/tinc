## Process this file with automake to get Makefile.in

AUTOMAKE_OPTIONS = gnits

SUBDIRS = m4 lib cipher src doc redhat

ACLOCAL_AMFLAGS = -I m4

EXTRA_DIST = TODO

ChangeLog:
	rcs2log -u "zarq	Ivo Timmermans	itimmermans@bigfoot.com" | \
	  sed -e 's,/home/CVS/tinc/cabal/,,g' > $@
