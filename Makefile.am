## Process this file with automake to get Makefile.in

AUTOMAKE_OPTIONS = gnu

SUBDIRS =  m4 lib src doc po

ACLOCAL_AMFLAGS = -I m4 

EXTRA_DIST = config.rpath mkinstalldirs have.h system.h COPYING.README depcomp

ChangeLog:
	svn log > ChangeLog

svn-clean: maintainer-clean
	svn status --no-ignore | sed -n 's/^[?I] \+//p' | tr '\012' '\0' | xargs -r0 rm -rf

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
