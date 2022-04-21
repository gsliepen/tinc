#include "unittest.h"
#include "../../src/utils.h"

static void test_int_to_str(const char *ref, int num) {
	char *result = int_to_str(num);
	assert_string_equal(ref, result);
	free(result);
}

static void test_int_to_str_return_expected(void **state) {
	(void)state;

	test_int_to_str("0", 0);
	test_int_to_str("-1337", -1337);
	test_int_to_str("65535", 65535);
}

static void test_is_decimal_fail_empty(void **state) {
	(void)state;

	assert_false(is_decimal(NULL));
	assert_false(is_decimal(""));
}

static void test_is_decimal_fail_hex(void **state) {
	(void)state;

	assert_false(is_decimal("DEADBEEF"));
	assert_false(is_decimal("0xCAFE"));
}

static void test_is_decimal_fail_junk_suffix(void **state) {
	(void)state;

	assert_false(is_decimal("123foobar"));
	assert_false(is_decimal("777 "));
}

static void test_is_decimal_pass_simple(void **state) {
	(void)state;

	assert_true(is_decimal("0"));
	assert_true(is_decimal("123"));
}

static void test_is_decimal_pass_signs(void **state) {
	(void)state;

	assert_true(is_decimal("-123"));
	assert_true(is_decimal("+123"));
}

static void test_is_decimal_pass_whitespace_prefix(void **state) {
	(void)state;

	assert_true(is_decimal(" \r\n\t 777"));
}

int main(void) {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_int_to_str_return_expected),
		cmocka_unit_test(test_is_decimal_fail_empty),
		cmocka_unit_test(test_is_decimal_fail_hex),
		cmocka_unit_test(test_is_decimal_fail_junk_suffix),
		cmocka_unit_test(test_is_decimal_pass_simple),
		cmocka_unit_test(test_is_decimal_pass_signs),
		cmocka_unit_test(test_is_decimal_pass_whitespace_prefix),
	};
	return cmocka_run_group_tests(tests, NULL, NULL);
}
