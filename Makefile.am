## Process this file with automake to get Makefile.in

AUTOMAKE_OPTIONS = gnu

SUBDIRS =  m4 lib src doc po

ACLOCAL_AMFLAGS = -I m4 

EXTRA_DIST = config.rpath mkinstalldirs system.h COPYING.README depcomp

CVS_CREATED = ABOUT-NLS INSTALL COPYING configure aclocal.m4 config.h.in config.guess \
 config.sub install-sh ltconfig ltmain.sh missing mkinstalldirs \
 stamp-h.in ChangeLog po/Makefile.in.in \
 po/tinc.pot po/*.sed po/*.header po/*.sin po/Rules-quot \
 src/.libs intl depcomp

ChangeLog:
	cvs2cl -U cvsusers --fsf

cvs-clean: maintainer-clean
	for f in $(CVS_CREATED) `find . -name Makefile.in` tinc-$(VERSION).tar.gz; do\
	  rm -Rf "$$f"; \
	done
	grep -l gettext `find m4 -type f` | xargs rm -f

deb:
	dpkg-buildpackage -rfakeroot

rpm: dist
	cp $(distdir).tar.gz /usr/src/redhat/SOURCES/
	cp redhat/tinc.spec /usr/src/redhat/SOURCES/
	cd /usr/src/redhat/SOURCES/ && rpm -bb tinc.spec

release:
	rm -f ChangeLog
	$(MAKE) ChangeLog
	echo "Please edit the NEWS file now..."
	/usr/bin/editor NEWS
	$(MAKE) dist
