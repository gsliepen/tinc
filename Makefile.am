## Process this file with automake to get Makefile.in

AUTOMAKE_OPTIONS = gnu

SUBDIRS = m4 intl lib src doc po redhat debian

ACLOCAL_AMFLAGS =

EXTRA_DIST = system.h ABOUT-NLS COPYING.README autogen.sh

CVS_CREATED = configure aclocal.m4 config.h.in config.guess \
 config.sub install-sh ltconfig ltmain.sh missing mkinstalldirs \
 stamp-h.in m4/Makefile.am ChangeLog po/Makefile.in.in \
 po/tinc.pot src/.libs intl

ChangeLog:
	rm -f ChangeLog
	cvs2cl -U cvsusers --fsf

cvs-clean: maintainer-clean
	for f in $(CVS_CREATED) `find -name Makefile.in` ; do\
	  rm -Rf "$$f"; \
	done

deb:
	dpkg-buildpackage -rfakeroot

rpm: dist
	cp $(distdir).tar.gz /usr/src/redhat/SOURCES/
	cp redhat/tinc.spec /usr/src/redhat/SOURCES/
	cd /usr/src/redhat/SOURCES/
	rpm -bi tinc.spec
