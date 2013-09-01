TESTS = \
	basic.test \
	executables.test \
	import-export.test \
	invite-join.test \
	sptps-basic.test

EXTRA_DIST = testlib.sh

clean-local:
	-for pid in *.test.?/pid; do ../src/tinc --pidfile="$$pid" stop; done
	-killall ../src/sptps_test
	-rm -rf *.test.?
