## Process this file with automake to get Makefile.in

AUTOMAKE_OPTIONS = gnits

SUBDIRS = m4 lib cipher src doc redhat

ACLOCAL_AMFLAGS = -I m4

EXTRA_DIST = TODO

CVS_CREATED = configure aclocal.m4 config.h.in

ChangeLog:
	rcs2log -u "zarq	Ivo Timmermans	itimmermans@bigfoot.com" | \
	  sed -e 's,/home/CVS/tinc/cabal/,,g' > $@

cvs-clean: maintainer-clean
	for f in $(CVS_CREATED) `find -name Makefile.in` ; do\
	  rm "$$f"; \
	  if [ $$? -ne 0 ] ; then \
	    echo $$f bestaat niet; \
	  fi; \
	done
