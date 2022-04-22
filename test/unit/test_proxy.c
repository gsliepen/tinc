#include "unittest.h"
#include "../../src/net.h"
#include "../../src/netutl.h"
#include "../../src/proxy.h"
#include "../../src/xalloc.h"

static const char *user = "foo";
static const size_t userlen = sizeof("foo") - 1;

static const char *pass = "bar";
static const size_t passlen = sizeof("bar") - 1;

static int teardown(void **state) {
	(void)state;

	free(proxyuser);
	proxyuser = NULL;

	free(proxypass);
	proxypass = NULL;

	free(proxyhost);
	proxyhost = NULL;

	return 0;
}

static void test_socks_req_len_socks4_ipv4(void **state) {
	(void)state;

	const sockaddr_t sa = str2sockaddr("127.0.0.1", "4242");

	size_t len = socks_req_len(PROXY_SOCKS4, &sa);
	assert_int_equal(9, len);

	proxyuser = xstrdup(user);
	len = socks_req_len(PROXY_SOCKS4, &sa);
	assert_int_equal(9 + userlen, len);
}

static void test_socks_req_len_socks4_ipv6(void **state) {
	(void)state;

	sockaddr_t sa = str2sockaddr("::1", "4242");
	size_t len = socks_req_len(PROXY_SOCKS4, &sa);
	assert_int_equal(0, len);
}

static void test_socks_req_len_socks5_ipv4(void **state) {
	(void)state;

	sockaddr_t sa = str2sockaddr("127.0.0.1", "4242");
	size_t baselen = 13;

	// Base test
	size_t len = socks_req_len(PROXY_SOCKS5, &sa);
	assert_int_equal(baselen, len);

	// Setting only password must not change result
	proxypass = xstrdup(pass);
	len = socks_req_len(PROXY_SOCKS5, &sa);
	assert_int_equal(baselen, len);

	// Setting both must
	proxyuser = xstrdup(user);
	len = socks_req_len(PROXY_SOCKS5, &sa);
	assert_int_equal(baselen + 3 + userlen + passlen, len);
}

static void test_socks_req_len_socks5_ipv6(void **state) {
	(void)state;

	sockaddr_t sa = str2sockaddr("::1", "4242");
	size_t baselen = 25;

	// Base test
	size_t len = socks_req_len(PROXY_SOCKS5, &sa);
	assert_int_equal(baselen, len);

	// Setting only user must not change result
	proxyuser = xstrdup(user);
	len = socks_req_len(PROXY_SOCKS5, &sa);
	assert_int_equal(baselen, len);

	// Setting both must
	proxypass = xstrdup(pass);
	len = socks_req_len(PROXY_SOCKS5, &sa);
	assert_int_equal(baselen + 3 + userlen + passlen, len);
}

static void test_socks_req_len_wrong_types(void **state) {
	(void)state;

	sockaddr_t sa = str2sockaddr("::1", "4242");

	assert_int_equal(0, socks_req_len(PROXY_NONE, &sa));
	assert_int_equal(0, socks_req_len(PROXY_SOCKS4A, &sa));
	assert_int_equal(0, socks_req_len(PROXY_HTTP, &sa));
	assert_int_equal(0, socks_req_len(PROXY_EXEC, &sa));
}

static void test_socks_req_len_wrong_family(void **state) {
	(void)state;

	sockaddr_t sa = {.sa.sa_family = AF_UNKNOWN};
	assert_int_equal(0, socks_req_len(PROXY_SOCKS4, &sa));
	assert_int_equal(0, socks_req_len(PROXY_SOCKS5, &sa));
}

static void test_check_socks_resp_wrong_types(void **state) {
	(void)state;

	uint8_t buf[512] = {0};
	assert_false(check_socks_resp(PROXY_NONE, buf, sizeof(buf)));
	assert_false(check_socks_resp(PROXY_SOCKS4A, buf, sizeof(buf)));
	assert_false(check_socks_resp(PROXY_HTTP, buf, sizeof(buf)));
	assert_false(check_socks_resp(PROXY_EXEC, buf, sizeof(buf)));
}

PACKED(struct socks4_response {
	uint8_t version;
	uint8_t status;
	uint16_t port;
	uint32_t addr;
});

static const uint32_t localhost_ipv4 = 0x7F000001;

static void test_check_socks_resp_socks4_ok(void **state) {
	(void)state;

	const struct socks4_response resp = {
		.version = 0x00,
		.status = 0x5A,
		.port = htons(12345),
		.addr = htonl(localhost_ipv4),
	};
	assert_true(check_socks_resp(PROXY_SOCKS4, &resp, sizeof(resp)));
}

static void test_check_socks_resp_socks4_bad(void **state) {
	(void)state;

	const uint8_t short_len[] = {0x00, 0x5A};
	assert_false(check_socks_resp(PROXY_SOCKS4, short_len, sizeof(short_len)));

	const struct socks4_response bad_version = {
		.version = 0x01,
		.status = 0x5A,
		.port = htons(12345),
		.addr = htonl(0x7F000001),
	};
	assert_false(check_socks_resp(PROXY_SOCKS4, &bad_version, sizeof(bad_version)));

	const struct socks4_response status_denied = {
		.version = 0x00,
		.status = 0x5B,
		.port = htons(12345),
		.addr = htonl(0x7F000001),
	};
	assert_false(check_socks_resp(PROXY_SOCKS4, &status_denied, sizeof(status_denied)));
}

PACKED(struct socks5_response {
	struct {
		uint8_t socks_version;
		uint8_t auth_method;
	} greet;

	struct {
		uint8_t version;
		uint8_t status;
	} auth;

	struct {
		uint8_t socks_version;
		uint8_t status;
		uint8_t reserved;
		uint8_t addr_type;

		union {
			struct {
				uint32_t addr;
				uint16_t port;
			} ipv4;

			struct {
				uint8_t addr[16];
				uint16_t port;
			} ipv6;
		};
	} resp;
});

PACKED(struct socks5_test_resp_t {
	socks5_resp_t resp;

	union {
		struct {
			uint32_t addr;
			uint16_t port;
		} ipv4;

		struct {
			uint8_t addr[16];
			uint16_t port;
		} ipv6;
	};
});

typedef struct socks5_test_resp_t socks5_test_resp_t;

static socks5_test_resp_t *make_good_socks5_ipv4(void) {
	static const socks5_test_resp_t reference = {
		.resp = {
			.choice = {.socks_version = 0x05, .auth_method = 0x02},
			.pass = {
				.status = {.auth_version = 0x01, .auth_status = 0x00},
				.resp = {
					.socks_version = 0x05,
					.conn_status = 0x00,
					.reserved = 0x00,
					.addr_type = 0x01,
				},
			},
		},
		.ipv4 = {.addr = 0x01020304, .port = 0x123},
	};

	socks5_test_resp_t *result = xmalloc(sizeof(socks5_test_resp_t));
	memcpy(result, &reference, sizeof(reference));
	return result;
}

static socks5_test_resp_t *make_good_socks5_ipv6(void) {
	static const socks5_test_resp_t reference = {
		.resp = {
			.choice = {.socks_version = 0x05, .auth_method = 0x02},
			.pass = {
				.status = {.auth_version = 0x01, .auth_status = 0x00},
				.resp = {
					.socks_version = 0x05,
					.conn_status = 0x00,
					.reserved = 0x00,
					.addr_type = 0x04,
				},
			},
		},
		.ipv6 = {
			.addr = {
				0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			},
			.port = 0x123,
		},
	};

	socks5_test_resp_t *result = xmalloc(sizeof(socks5_test_resp_t));
	memcpy(result, &reference, sizeof(reference));
	return result;
}

static void test_check_socks_resp_socks5_ok_ipv4(void **state) {
	(void)state;

	socks5_test_resp_t *resp = make_good_socks5_ipv4();
	assert_true(check_socks_resp(PROXY_SOCKS5, resp, sizeof(*resp)));
	free(resp);
}

static void test_check_socks_resp_socks5_ok_ipv6(void **state) {
	(void)state;

	socks5_test_resp_t *resp = make_good_socks5_ipv6();
	assert_true(check_socks_resp(PROXY_SOCKS5, resp, sizeof(*resp)));
	free(resp);
}

static void test_check_socks_resp_socks5_short(void **state) {
	(void)state;

	const uint8_t resp[] = {0x05, 0x02};
	assert_false(check_socks_resp(PROXY_SOCKS5, resp, sizeof(resp)));
}

// Define a test that assigns a bad value to one of the fields and checks that it fails
#define BREAK_SOCKS5_FIELD_TEST(proto, name, expr)                                   \
	static void test_check_socks_resp_socks5_bad_##name##_##proto(void **state) {    \
		(void)state;                                                                 \
		socks5_test_resp_t *resp = make_good_socks5_##proto();                       \
		assert_true(check_socks_resp(PROXY_SOCKS5, resp, sizeof(*resp)));            \
		expr;                                                                        \
		assert_false(check_socks_resp(PROXY_SOCKS5, resp, sizeof(*resp)));           \
		free(resp);                                                                  \
	}

// Define a test group for IPv4 or IPv6
#define BREAK_SOCKS5_TEST_GROUP(proto) \
	BREAK_SOCKS5_FIELD_TEST(proto, resp_socks_version,   resp->resp.pass.resp.socks_version = 0x4)  \
	BREAK_SOCKS5_FIELD_TEST(proto, resp_conn_status,     resp->resp.pass.resp.conn_status = 0x1)    \
	BREAK_SOCKS5_FIELD_TEST(proto, resp_addr_type,       resp->resp.pass.resp.addr_type = 0x42)     \
	BREAK_SOCKS5_FIELD_TEST(proto, choice_socks_version, resp->resp.choice.socks_version = 0x04)    \
	BREAK_SOCKS5_FIELD_TEST(proto, choice_auth_method,   resp->resp.choice.auth_method = 0x12)      \
	BREAK_SOCKS5_FIELD_TEST(proto, status_auth_version,  resp->resp.pass.status.auth_version = 0x2) \
	BREAK_SOCKS5_FIELD_TEST(proto, status_auth_status,   resp->resp.pass.status.auth_status = 0x1)

BREAK_SOCKS5_TEST_GROUP(ipv4)
BREAK_SOCKS5_TEST_GROUP(ipv6)

static void test_create_socks_req_socks4(void **state) {
	(void)state;

	const uint8_t ref[8] = {0x04, 0x01, 0x00, 0x7b, 0x01, 0x01, 0x01, 0x01};
	const sockaddr_t sa = str2sockaddr("1.1.1.1", "123");

	uint8_t buf[512];
	assert_int_equal(sizeof(ref), create_socks_req(PROXY_SOCKS4, buf, &sa));
	assert_memory_equal(ref, buf, sizeof(ref));
}

static void test_create_socks_req_socks5_ipv4_anon(void **state) {
	(void) state;

	const sockaddr_t sa = str2sockaddr("2.2.2.2", "16962");

	const uint8_t ref[13] = {
		0x05, 0x01, 0x00,
		0x05, 0x01, 0x00, 0x01, 0x02, 0x02, 0x02, 0x02, 0x42, 0x42,
	};

	uint8_t buf[sizeof(ref)];
	assert_int_equal(12, create_socks_req(PROXY_SOCKS5, buf, &sa));
	assert_memory_equal(ref, buf, sizeof(ref));
}

static void test_create_socks_req_socks5_ipv4_password(void **state) {
	(void)state;

	proxyuser = xstrdup(user);
	proxypass = xstrdup(pass);

	const sockaddr_t sa = str2sockaddr("2.2.2.2", "16962");

	const uint8_t ref[22] = {
		0x05, 0x01, 0x02,
		0x01, (uint8_t)userlen, 'f', 'o', 'o', (uint8_t)passlen, 'b', 'a', 'r',
		0x05, 0x01, 0x00, 0x01, 0x02, 0x02, 0x02, 0x02, 0x42, 0x42,
	};

	uint8_t buf[sizeof(ref)];
	assert_int_equal(14, create_socks_req(PROXY_SOCKS5, buf, &sa));
	assert_memory_equal(ref, buf, sizeof(ref));
}

static void test_create_socks_req_socks5_ipv6_anon(void **state) {
	(void)state;

	const sockaddr_t sa = str2sockaddr("1111:2222::3333:4444:5555", "18504");

	const uint8_t ref[25] = {
		0x05, 0x01, 0x00,
		0x05, 0x01, 0x00, 0x04,
		0x11, 0x11, 0x22, 0x22, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x33, 0x33, 0x44, 0x44, 0x55, 0x55,
		0x48, 0x48,
	};

	uint8_t anon_buf[sizeof(ref)];
	assert_int_equal(24, create_socks_req(PROXY_SOCKS5, anon_buf, &sa));
	assert_memory_equal(ref, anon_buf, sizeof(ref));
}


static void test_create_socks_req_socks5_ipv6_password(void **state) {
	(void)state;

	proxyuser = xstrdup(user);
	proxypass = xstrdup(pass);

	const sockaddr_t sa = str2sockaddr("4444:2222::6666:4444:1212", "12850");

	const uint8_t ref[34] = {
		0x05, 0x01, 0x02,
		0x01, (uint8_t)userlen, 'f', 'o', 'o', (uint8_t)passlen, 'b', 'a', 'r',
		0x05, 0x01, 0x00, 0x04,
		0x44, 0x44, 0x22, 0x22, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x66, 0x66, 0x44, 0x44, 0x12, 0x12,
		0x32, 0x32,
	};

	uint8_t anon_buf[sizeof(ref)];
	assert_int_equal(26, create_socks_req(PROXY_SOCKS5, anon_buf, &sa));
	assert_memory_equal(ref, anon_buf, sizeof(ref));
}

int main(void) {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test_teardown(test_socks_req_len_socks4_ipv4, teardown),
		cmocka_unit_test_teardown(test_socks_req_len_socks4_ipv6, teardown),
		cmocka_unit_test_teardown(test_socks_req_len_socks5_ipv4, teardown),
		cmocka_unit_test_teardown(test_socks_req_len_socks5_ipv6, teardown),
		cmocka_unit_test_teardown(test_socks_req_len_wrong_types, teardown),
		cmocka_unit_test_teardown(test_socks_req_len_wrong_family, teardown),

		cmocka_unit_test(test_check_socks_resp_wrong_types),
		cmocka_unit_test(test_check_socks_resp_socks4_ok),
		cmocka_unit_test(test_check_socks_resp_socks4_bad),
		cmocka_unit_test(test_check_socks_resp_socks5_ok_ipv4),
		cmocka_unit_test(test_check_socks_resp_socks5_ok_ipv6),
		cmocka_unit_test(test_check_socks_resp_socks5_short),

		cmocka_unit_test(test_check_socks_resp_socks5_bad_resp_socks_version_ipv4),
		cmocka_unit_test(test_check_socks_resp_socks5_bad_resp_conn_status_ipv4),
		cmocka_unit_test(test_check_socks_resp_socks5_bad_resp_addr_type_ipv4),
		cmocka_unit_test(test_check_socks_resp_socks5_bad_choice_socks_version_ipv4),
		cmocka_unit_test(test_check_socks_resp_socks5_bad_choice_auth_method_ipv4),
		cmocka_unit_test(test_check_socks_resp_socks5_bad_status_auth_version_ipv4),
		cmocka_unit_test(test_check_socks_resp_socks5_bad_status_auth_status_ipv4),

		cmocka_unit_test(test_check_socks_resp_socks5_bad_resp_socks_version_ipv6),
		cmocka_unit_test(test_check_socks_resp_socks5_bad_resp_conn_status_ipv6),
		cmocka_unit_test(test_check_socks_resp_socks5_bad_resp_addr_type_ipv6),
		cmocka_unit_test(test_check_socks_resp_socks5_bad_choice_socks_version_ipv6),
		cmocka_unit_test(test_check_socks_resp_socks5_bad_choice_auth_method_ipv6),
		cmocka_unit_test(test_check_socks_resp_socks5_bad_status_auth_version_ipv6),
		cmocka_unit_test(test_check_socks_resp_socks5_bad_status_auth_status_ipv6),

		cmocka_unit_test_teardown(test_create_socks_req_socks4, teardown),
		cmocka_unit_test_teardown(test_create_socks_req_socks5_ipv4_anon, teardown),
		cmocka_unit_test_teardown(test_create_socks_req_socks5_ipv4_password, teardown),
		cmocka_unit_test_teardown(test_create_socks_req_socks5_ipv6_anon, teardown),
		cmocka_unit_test_teardown(test_create_socks_req_socks5_ipv6_password, teardown),
	};
	return cmocka_run_group_tests(tests, NULL, NULL);
}
