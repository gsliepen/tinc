// Test that randomize() kills the process when called without initialization

#include "unittest.h"

#ifdef HAVE_GETENTROPY
int main(void) {
	return 1;
}
#else
#include "../../src/random.h"

int main(void) {
	uint8_t buf[16];
	randomize(buf, sizeof(buf));
	return 0;
}
#endif // HAVE_GETENTROPY
