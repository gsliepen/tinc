## Process this file with automake to get Makefile.in

AUTOMAKE_OPTIONS = gnu

SUBDIRS =  src doc test systemd bash_completion.d

ACLOCAL_AMFLAGS = -I m4

EXTRA_DIST = COPYING.README README.md README.android SECURITY.md

@CODE_COVERAGE_RULES@

.PHONY: extra
extra:
	$(MAKE) -C $(srcdir)/src extra
	$(MAKE) -C $(srcdir)/test extra

# If git describe works, force autoconf to run in order to make sure we have the
# current version number from git in the resulting configure script.
configure-version:
	-cd $(srcdir) && git describe && autoconf --force

# Triggering the README target means we are building a distribution (make dist).
README: configure-version README.md
	ln -sf README.md README

CLEANFILES = README

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

astyle:
	astyle --options=.astylerc -nQ src/*.[ch] src/*/*.[ch]
