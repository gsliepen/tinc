## Process this file with automake to get Makefile.in

AUTOMAKE_OPTIONS = gnu

SUBDIRS =  m4 src doc gui

ACLOCAL_AMFLAGS = -I m4 

EXTRA_DIST = COPYING.README README.android

ChangeLog:
	git log > ChangeLog

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
