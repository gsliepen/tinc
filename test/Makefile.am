TESTS = \
	basic.test \
	commandline.test \
	executables.test \
	import-export.test \
	invite-join.test \
	sptps-basic.test \
	variables.test

EXTRA_DIST = testlib.sh

clean-local:
	-for pid in *.test.?/pid; do ../src/tinc --pidfile="$$pid" stop; done
	-killall ../src/sptps_test
	-rm -rf *.test.?
