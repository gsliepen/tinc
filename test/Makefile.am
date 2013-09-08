TESTS = \
	basic.test \
	commandline.test \
	executables.test \
	import-export.test \
	invite-join.test \
	ping.test \
	sptps-basic.test \
	variables.test

dist_check_SCRIPTS = $(TESTS)

EXTRA_DIST = testlib.sh

check_PROGRAMS = pong

pong_SOURCES = pong.c

clean-local:
	-for pid in *.test.?/pid; do ../src/tinc --pidfile="$$pid" stop; done
	-killall ../src/sptps_test
	-killall pong
	-rm -rf *.test.?
