## Process this file with automake to get Makefile.in

AUTOMAKE_OPTIONS = gnu

SUBDIRS = src doc systemd

ACLOCAL_AMFLAGS = -I m4 

EXTRA_DIST = COPYING.README README.android

ChangeLog:
	git log > ChangeLog

astyle:
	astyle --options=.astylerc -nQ src/*.[ch] src/*/*.[ch]
