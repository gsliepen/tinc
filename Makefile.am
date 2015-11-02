## Process this file with automake to get Makefile.in

AUTOMAKE_OPTIONS = gnu

SUBDIRS =  src doc gui test systemd

ACLOCAL_AMFLAGS = -I m4

EXTRA_DIST = COPYING.README README.android

# If git describe works, force autoconf to run in order to make sure we have the
# current version number from git in the resulting configure script.
configure-version:
	-cd $(srcdir) && git describe && autoconf --force

# Triggering the README target means we are building a distribution (make dist).
README: configure-version

ChangeLog:
	(cd $(srcdir) && git log) > ChangeLog

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
	/usr/bin/editor $(srcdir)/NEWS
	$(MAKE) dist
