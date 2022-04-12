// Test that randomize() kills the process when called without initialization

#include "unittest.h"

#ifdef HAVE_GETRANDOM
int main(void) {
	return 1;
}
#else
#include "../../src/random.h"

static void on_abort(int sig) {
	(void)sig;
	exit(1);
}

int main(void) {
	signal(SIGABRT, on_abort);
	u_int8_t buf[16];
	randomize(buf, sizeof(buf));
	return 0;
}
#endif // HAVE_GETRANDOM
