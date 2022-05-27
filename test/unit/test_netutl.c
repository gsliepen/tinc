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

static void test_is_local_connection_ipv4(void **state) {
	(void)state;

	sockaddr_t sa;

	assert_true(inet_pton(AF_INET, "127.0.0.0", &sa.in.sin_addr));
	sa.sa.sa_family = AF_INET;
	assert_true(is_local_connection(&sa));

	assert_true(inet_pton(AF_INET, "127.42.13.5", &sa.in.sin_addr));
	sa.sa.sa_family = AF_INET;
	assert_true(is_local_connection(&sa));

	assert_true(inet_pton(AF_INET, "127.255.255.255", &sa.in.sin_addr));
	sa.sa.sa_family = AF_INET;
	assert_true(is_local_connection(&sa));

	assert_true(inet_pton(AF_INET, "128.0.0.1", &sa.in.sin_addr));
	sa.sa.sa_family = AF_INET;
	assert_false(is_local_connection(&sa));
}

static void test_is_local_connection_ipv6(void **state) {
	(void)state;

	sockaddr_t sa;

	assert_true(inet_pton(AF_INET6, "::1", &sa.in6.sin6_addr));
	sa.sa.sa_family = AF_INET6;
	assert_true(is_local_connection(&sa));

	assert_true(inet_pton(AF_INET6, "::1:1", &sa.in6.sin6_addr));
	sa.sa.sa_family = AF_INET6;
	assert_false(is_local_connection(&sa));

	assert_true(inet_pton(AF_INET6, "fe80::", &sa.in6.sin6_addr));
	sa.sa.sa_family = AF_INET6;
	assert_false(is_local_connection(&sa));
}

static void test_is_local_connection_unix(void **state) {
	(void)state;

	sockaddr_t sa = {.sa.sa_family = AF_UNIX};
	assert_true(is_local_connection(&sa));
}

int main(void) {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_service_to_port_invalid),
		cmocka_unit_test(test_service_to_port_valid),
		cmocka_unit_test(test_is_local_connection_ipv4),
		cmocka_unit_test(test_is_local_connection_ipv6),
		cmocka_unit_test(test_is_local_connection_unix),
	};
	return cmocka_run_group_tests(tests, NULL, NULL);
}
