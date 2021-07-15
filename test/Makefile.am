TESTS = \
	basic.test \
	executables.test \
	commandline.test \
	import-export.test \
	invite-join.test \
	invite-offline.test \
	invite-tinc-up.test \
	variables.test \
	scripts.test \
	security.test

if WITH_LEGACY_PROTOCOL
TESTS += legacy-protocol.test

if !MINGW
TESTS += algorithms.test
endif
endif

if !MINGW
TESTS += sptps-basic.test
endif

if LINUX
TESTS += ns-ping.test
endif

dist_check_SCRIPTS = $(TESTS)

AM_CFLAGS = -iquote.

check_PROGRAMS = \
	splice

splice_SOURCES = splice.c

clean-local:
	-for pid in *.test.?/pid; do ../src/tinc --pidfile="$$pid" stop; done
	-killall ../src/sptps_test
	-rm -rf *.test.?
