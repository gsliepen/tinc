#include "unittest.h"
#include "../../src/utils.h"

#define FAKE_PATH "nonexistentreallyfakepath"

typedef struct {
	const char *arg;
	const char *want;
} testcase_t;

static void test_unix_absolute_path_on_absolute_returns_it(void **state) {
	(void)state;

	const char *paths[] = {"/", "/foo", "/foo/./../bar"};

	for(size_t i = 0; i < sizeof(paths) / sizeof(*paths); ++i) {
		char *got = absolute_path(paths[i]);
		assert_ptr_not_equal(paths[i], got);
		assert_string_equal(paths[i], got);
		free(got);
	}
}

static void test_unix_absolute_path_on_empty_returns_null(void **state) {
	(void)state;
	assert_null(absolute_path(NULL));
	assert_null(absolute_path("\0"));
}

static void test_unix_absolute_path_relative(void **state) {
	(void)state;

	testcase_t cases[] = {
		{".", "/"},
		{"foo", "/foo"},
		{"./"FAKE_PATH, "/./"FAKE_PATH},
		{"../foo/./../"FAKE_PATH, "/../foo/./../"FAKE_PATH},
	};

	for(size_t i = 0; i < sizeof(cases) / sizeof(*cases); ++i) {
		char *got = absolute_path(cases[i].arg);
		assert_string_equal(cases[i].want, got);
		free(got);
	}
}

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

static int setup_path_unix(void **state) {
	(void)state;
	assert_int_equal(0, chdir("/"));
	return 0;
}

int main(void) {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test_setup(test_unix_absolute_path_on_absolute_returns_it, setup_path_unix),
		cmocka_unit_test_setup(test_unix_absolute_path_on_empty_returns_null, setup_path_unix),
		cmocka_unit_test_setup(test_unix_absolute_path_relative, setup_path_unix),
		cmocka_unit_test(test_int_to_str_return_expected),
		cmocka_unit_test(test_is_decimal_fail_empty),
		cmocka_unit_test(test_is_decimal_fail_hex),
		cmocka_unit_test(test_is_decimal_fail_junk_suffix),
		cmocka_unit_test(test_is_decimal_pass_simple),
		cmocka_unit_test(test_is_decimal_pass_signs),
		cmocka_unit_test(test_is_decimal_pass_whitespace_prefix),
	};

#ifdef HAVE_WINDOWS
	cmocka_set_skip_filter("test_unix_*");
#endif

	return cmocka_run_group_tests(tests, NULL, NULL);
}
