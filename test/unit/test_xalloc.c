#include "unittest.h"
#include "../../src/xalloc.h"

static const uint8_t ref[] = {0, 1, 2, 3, 4, 5, 6, 7};

static void test_memzero_wipes_partial(void **state) {
	(void)state;

	uint8_t buf[sizeof(ref)];
	memcpy(buf, ref, sizeof(buf));

	const size_t len = 2;
	memzero(buf, len);
	assert_int_equal(0, buf[0]);
	assert_int_equal(0, buf[1]);

	assert_memory_equal(&buf[len], &ref[len], sizeof(ref) - len);
}

static void test_memzero_wipes_buffer(void **state) {
	(void)state;

	uint8_t buf[sizeof(ref)];
	uint8_t zero[sizeof(ref)] = {0};

	memcpy(buf, ref, sizeof(buf));
	assert_memory_equal(ref, buf, sizeof(buf));

	memzero(buf, sizeof(buf));
	assert_memory_not_equal(buf, ref, sizeof(buf));
	assert_memory_equal(zero, buf, sizeof(buf));
}

static void test_memzero_zerolen_does_not_change_memory(void **state) {
	(void)state;

	uint8_t buf[sizeof(ref)];

	memcpy(buf, ref, sizeof(buf));
	assert_memory_equal(ref, buf, sizeof(buf));

	memzero(buf, 0);
	assert_memory_equal(ref, buf, sizeof(buf));
}

// This test will fail under ASAN if xzfree forgets to call free() or overflows the buffer
static void test_xzfree_frees_memory(void **state) {
	(void)state;

	xzfree(xmalloc(64), 64);
}

int main(void) {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_memzero_wipes_partial),
		cmocka_unit_test(test_memzero_wipes_buffer),
		cmocka_unit_test(test_memzero_zerolen_does_not_change_memory),
		cmocka_unit_test(test_xzfree_frees_memory),
	};
	return cmocka_run_group_tests(tests, NULL, NULL);
}
