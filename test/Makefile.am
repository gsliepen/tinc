TESTS = \
	basic.test \
	commandline.test \
	executables.test \
	import-export.test \
	invite-join.test \
	invite-offline.test \
	invite-tinc-up.test \
	ns-ping.test \
	scripts.test \
	sptps-basic.test \
	variables.test

dist_check_SCRIPTS = $(TESTS)

EXTRA_DIST = testlib.sh

AM_CFLAGS = -iquote.

clean-local:
	-for pid in *.test.?/pid; do ../src/tinc --pidfile="$$pid" stop; done
	-killall ../src/sptps_test
	-rm -rf *.test.?
