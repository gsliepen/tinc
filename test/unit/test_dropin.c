#include "unittest.h"

static const char buf[3];

static void test_min(void **state) {
	(void)state;

	assert_int_equal(-1, MIN(1, -1));
	assert_int_equal(-2, MIN(1 + 2 * 3, 3 - 2 * 5 / 2));

	assert_ptr_equal(buf[0], MIN(buf[1], buf[0]));
}

static void test_max(void **state) {
	(void)state;

	assert_int_equal(1, MAX(1, -1));
	assert_int_equal(4, MAX(1 + 3 - 3 / 4 * 5, 10 / 5 + 2 - 2));

	assert_ptr_equal(buf[1], MAX(buf[1], buf[0]));
}

static void test_clamp(void **state) {
	(void)state;

	assert_int_equal(10, CLAMP(INT_MAX, -10, 10));
	assert_int_equal(-10, CLAMP(INT_MIN, -10, 10));
	assert_int_equal(7, CLAMP(3 + 4, 6, 8));

	assert_int_equal(5, CLAMP(-1000, 5, 5));
	assert_int_equal(5, CLAMP(0,     5, 5));
	assert_int_equal(5, CLAMP(1000,  5, 5));

	assert_ptr_equal(buf[1], CLAMP(buf[2], buf[0], buf[1]));
}

int main(void) {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_min),
		cmocka_unit_test(test_max),
		cmocka_unit_test(test_clamp),
	};
	return cmocka_run_group_tests(tests, NULL, NULL);
}
