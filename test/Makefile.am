TESTS = \
	basic.test \
	commandline.test \
	executables.test \
	import-export.test \
	invite-join.test \
	invite-offline.test \
	invite-tinc-up.test \
	legacy-protocol.test \
	ns-ping.test \
	scripts.test \
	security.test \
	sptps-basic.test \
	variables.test

dist_check_SCRIPTS = $(TESTS)

EXTRA_DIST = testlib.sh

AM_CFLAGS = -iquote.

check_PROGRAMS = \
	splice

splice_SOURCES = splice.c

clean-local:
	-for pid in *.test.?/pid; do ../src/tinc --pidfile="$$pid" stop; done
	-killall ../src/sptps_test
	-rm -rf *.test.?
