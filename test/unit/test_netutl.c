#include "unittest.h"
#include "../../src/netutl.h"

static void test_service_to_port_invalid(void **state) {
	(void)state;

	assert_int_equal(0, service_to_port(NULL));
	assert_int_equal(0, service_to_port(""));
	assert_int_equal(0, service_to_port("-1"));
	assert_int_equal(0, service_to_port("foobar"));
}

static void test_service_to_port_valid(void **state) {
	(void)state;

	assert_int_equal(22, service_to_port("ssh"));
	assert_int_equal(80, service_to_port("http"));
	assert_int_equal(443, service_to_port("https"));
	assert_int_equal(1234, service_to_port("1234"));
}

int main(void) {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_service_to_port_invalid),
		cmocka_unit_test(test_service_to_port_valid),
	};
	return cmocka_run_group_tests(tests, NULL, NULL);
}
