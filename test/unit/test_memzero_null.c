// Test that memzero() with NULL pointer crashes the program

#include "config.h"
#undef HAVE_ATTR_NONNULL

#include "unittest.h"
#include "../../src/xalloc.h"

int main(void) {
	memzero(NULL, 1);
	return 0;
}
