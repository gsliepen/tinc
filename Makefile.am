## Process this file with automake to get Makefile.in

AUTOMAKE_OPTIONS = gnu

SUBDIRS = m4 lib cipher src doc redhat debian

ACLOCAL_AMFLAGS =

EXTRA_DIST = 

CVS_CREATED = configure aclocal.m4 config.h.in config.guess \
 config.sub install-sh ltconfig ltmain.sh missing mkinstalldirs \
 stamp-h.in m4/Makefile.am ChangeLog

ChangeLog:
	rm -f ChangeLog
	rcs2log -u "zarq	Ivo Timmermans	itimmermans@bigfoot.com" \
	  -u "guus	Guus Sliepen	guus@sliepen.warande.net" | \
	  sed -e 's,/home/CVS/tinc/cabal/,,g' > $@

cvs-clean: maintainer-clean
	for f in $(CVS_CREATED) `find -name Makefile.in` ; do\
	  rm -f "$$f"; \
	done

deb:
	dpkg-buildpackage -rfakeroot
