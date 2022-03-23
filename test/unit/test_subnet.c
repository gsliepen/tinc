#include "unittest.h"
#include "../../src/subnet.h"

typedef struct net_str_testcase {
	const char *text;
	subnet_t data;
} net_str_testcase;

static void test_subnet_compare_different_types(void **state) {
	(void)state;

	const subnet_t ipv4 = {.type = SUBNET_IPV4};
	const subnet_t ipv6 = {.type = SUBNET_IPV6};
	const subnet_t mac = {.type = SUBNET_MAC};

	assert_int_not_equal(0, subnet_compare(&ipv4, &ipv6));
	assert_int_not_equal(0, subnet_compare(&ipv4, &mac));
	assert_int_not_equal(0, subnet_compare(&ipv6, &mac));
}

static const mac_t mac1 = {{0x00, 0x01, 0x02, 0x03, 0x04, 0x05}};
static const mac_t mac2 = {{0x42, 0x01, 0x02, 0x03, 0x04, 0x05}};

static const subnet_ipv4_t ipv4_1 = {.address = {{0x01, 0x02, 0x03, 0x04}}, .prefixlength = 24};
static const subnet_ipv4_t ipv4_1_pref = {.address = {{0x01, 0x02, 0x03, 0x04}}, .prefixlength = 16};
static const subnet_ipv4_t ipv4_2 = {.address = {{0x11, 0x22, 0x33, 0x44}}, .prefixlength = 16};

static const subnet_ipv6_t ipv6_1 = {
	.address = {{0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04}},
	.prefixlength = 24
};

static const subnet_ipv6_t ipv6_1_pref = {
	.address = {{0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04}},
	.prefixlength = 16
};

static const subnet_ipv6_t ipv6_2 = {
	.address = {{0x11, 0x22, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04}},
	.prefixlength = 24
};

static void test_maskcmp(void **state) {
	(void)state;

	const ipv4_t a = {{1, 2, 3, 4}};
	const ipv4_t b = {{1, 2, 3, 0xff}};

	for(int mask = 0; mask <= 24; ++mask) {
		assert_int_equal(0, maskcmp(&a, &b, mask));
	}

	for(int mask = 25; mask <= 32; ++mask) {
		assert_true(maskcmp(&a, &b, mask) != 0);
	}
}

static void test_mask(void **state) {
	(void)state;

	ipv4_t dst = {{0xff, 0xff, 0xff, 0xff}};
	mask(&dst, 23, sizeof(dst));

	const ipv4_t ref = {{0xff, 0xff, 0xfe, 0x00}};
	assert_memory_equal(&ref, &dst, sizeof(dst));
}

static void test_maskcpy(void **state) {
	(void)state;

	const ipv4_t src = {{0xff, 0xff, 0xff, 0xff}};
	const ipv4_t ref = {{0xff, 0xff, 0xfe, 0x00}};
	ipv4_t dst;

	maskcpy(&dst, &src, 23, sizeof(src));

	assert_memory_equal(&ref, &dst, sizeof(dst));
}

static void test_subnet_compare_mac_eq(void **state) {
	(void)state;

	node_t owner = {.name = strdup("foobar")};
	const subnet_t a = {.type = SUBNET_MAC, .net.mac.address = mac1, .weight = 42, .owner = &owner};
	const subnet_t b = {.type = SUBNET_MAC, .net.mac.address = mac1, .weight = 42, .owner = &owner};

	assert_int_equal(0, subnet_compare(&a, &a));
	assert_int_equal(0, subnet_compare(&a, &b));
	assert_int_equal(0, subnet_compare(&b, &a));

	free(owner.name);
}

static void test_subnet_compare_mac_neq_address(void **state) {
	(void)state;

	node_t owner = {.name = strdup("foobar")};
	const subnet_t a = {.type = SUBNET_MAC, .net.mac.address = mac1, .weight = 10, .owner = &owner};
	const subnet_t b = {.type = SUBNET_MAC, .net.mac.address = mac2, .weight = 10, .owner = &owner};

	assert_true(subnet_compare(&a, &b) < 0);
	assert_true(subnet_compare(&b, &a) > 0);

	free(owner.name);
}

static void test_subnet_compare_mac_weight(void **state) {
	(void)state;

	node_t owner = {.name = strdup("foobar")};
	const subnet_t a = {.type = SUBNET_MAC, .net.mac.address = mac1, .weight = 42, .owner = &owner};
	const subnet_t b = {.type = SUBNET_MAC, .net.mac.address = mac1, .weight = 42, .owner = &owner};
	const subnet_t c = {.type = SUBNET_MAC, .net.mac.address = mac1, .weight = 10, .owner = &owner};

	assert_int_equal(0, subnet_compare(&a, &a));
	assert_int_equal(0, subnet_compare(&a, &b));
	assert_int_equal(0, subnet_compare(&b, &a));

	assert_true(subnet_compare(&a, &c) > 0);
	assert_true(subnet_compare(&c, &a) < 0);

	free(owner.name);
}

static void test_subnet_compare_mac_owners(void **state) {
	(void)state;

	node_t foo = {.name = strdup("foo")};
	node_t bar = {.name = strdup("bar")};

	const subnet_t a = {.type = SUBNET_MAC, .net.mac.address = mac1, .weight = 42, .owner = &foo};
	const subnet_t b = {.type = SUBNET_MAC, .net.mac.address = mac1, .weight = 42, .owner = &bar};

	assert_int_equal(0, subnet_compare(&a, &a));
	assert_int_equal(0, subnet_compare(&b, &b));

	assert_true(subnet_compare(&a, &b) > 0);
	assert_true(subnet_compare(&b, &a) < 0);

	free(foo.name);
	free(bar.name);
}


static void test_subnet_compare_ipv4_eq(void **state) {
	(void)state;

	const subnet_t a = {.type = SUBNET_IPV4, .net.ipv4 = ipv4_1};
	const subnet_t b = {.type = SUBNET_IPV4, .net.ipv4 = ipv4_1};

	assert_int_equal(0, subnet_compare(&a, &b));
	assert_int_equal(0, subnet_compare(&b, &a));
}

static void test_subnet_compare_ipv4_neq(void **state) {
	(void)state;

	const subnet_t a = {.type = SUBNET_IPV4, .net.ipv4 = ipv4_1};
	const subnet_t b = {.type = SUBNET_IPV4, .net.ipv4 = ipv4_1_pref};
	const subnet_t c = {.type = SUBNET_IPV4, .net.ipv4 = ipv4_2};

	assert_true(subnet_compare(&a, &b) < 0);
	assert_true(subnet_compare(&b, &a) > 0);

	assert_true(subnet_compare(&a, &c) < 0);
	assert_true(subnet_compare(&b, &c) < 0);
}

static void test_subnet_compare_ipv4_weight(void **state) {
	(void)state;

	const subnet_t a = {.type = SUBNET_IPV4, .net.ipv4 = ipv4_1, .weight = 1};
	const subnet_t b = {.type = SUBNET_IPV4, .net.ipv4 = ipv4_1, .weight = 2};

	assert_true(subnet_compare(&a, &b) < 0);
}

static void test_subnet_compare_ipv4_owners(void **state) {
	(void)state;

	node_t foo = {.name = strdup("foo")};
	node_t bar = {.name = strdup("bar")};

	const subnet_t a = {.type = SUBNET_IPV4, .net.ipv4 = ipv4_1, .owner = &foo};
	const subnet_t b = {.type = SUBNET_IPV4, .net.ipv4 = ipv4_1, .owner = &foo};
	const subnet_t c = {.type = SUBNET_IPV4, .net.ipv4 = ipv4_1, .owner = &bar};

	assert_int_equal(0, subnet_compare(&a, &b));
	assert_true(subnet_compare(&a, &c) > 0);

	free(foo.name);
	free(bar.name);
}

static void test_subnet_compare_ipv6_eq(void **state) {
	(void)state;

	const subnet_t a = {.type = SUBNET_IPV6, .net.ipv6 = ipv6_1};
	const subnet_t b = {.type = SUBNET_IPV6, .net.ipv6 = ipv6_1};

	assert_int_equal(0, subnet_compare(&a, &b));
	assert_int_equal(0, subnet_compare(&b, &a));
}

static void test_subnet_compare_ipv6_neq(void **state) {
	(void)state;

	const subnet_t a = {.type = SUBNET_IPV6, .net.ipv6 = ipv6_1};
	const subnet_t b = {.type = SUBNET_IPV6, .net.ipv6 = ipv6_1_pref};
	const subnet_t c = {.type = SUBNET_IPV6, .net.ipv6 = ipv6_2};

	assert_true(subnet_compare(&a, &b) < 0);
	assert_true(subnet_compare(&b, &a) > 0);

	assert_true(subnet_compare(&a, &c) < 0);
	assert_true(subnet_compare(&b, &c) > 0);
}

static void test_subnet_compare_ipv6_weight(void **state) {
	(void)state;

	const subnet_t a = {.type = SUBNET_IPV6, .net.ipv6 = ipv6_1, .weight = 1};
	const subnet_t b = {.type = SUBNET_IPV6, .net.ipv6 = ipv6_1, .weight = 2};

	assert_true(subnet_compare(&a, &b) < 0);
}

static void test_subnet_compare_ipv6_owners(void **state) {
	(void)state;

	node_t foo = {.name = strdup("foo")};
	node_t bar = {.name = strdup("bar")};

	const subnet_t a = {.type = SUBNET_IPV6, .net.ipv6 = ipv6_1, .owner = &foo};
	const subnet_t b = {.type = SUBNET_IPV6, .net.ipv6 = ipv6_1, .owner = &foo};
	const subnet_t c = {.type = SUBNET_IPV6, .net.ipv6 = ipv6_1, .owner = &bar};

	assert_int_equal(0, subnet_compare(&a, &b));
	assert_true(subnet_compare(&a, &c) > 0);

	free(foo.name);
	free(bar.name);
}

static void test_str2net_valid(void **state) {
	(void)state;

	const net_str_testcase testcases[] = {
		{
			.text = "1.2.3.0/24#42",
			.data = {
				.type = SUBNET_IPV4,
				.weight = 42,
				.net = {
					.ipv4 = {
						.address = {
							.x = {1, 2, 3, 0}
						},
						.prefixlength = 24,
					},
				},
			},
		},
		{
			.text = "04fb:7deb:78db:1950:2d21:258d:40b6:f0d7/128#999",
			.data = {
				.type = SUBNET_IPV6,
				.weight = 999,
				.net = {
					.ipv6 = {
						.address = {
							.x = {
								htons(0x04fb), htons(0x7deb), htons(0x78db), htons(0x1950),
								htons(0x2d21), htons(0x258d), htons(0x40b6), htons(0xf0d7),
							}
						},
						.prefixlength = 128,
					},
				},
			},
		},
		{
			.text = "fe80::16dd:a9ff:fe7e:b4c2/64",
			.data = {
				.type = SUBNET_IPV6,
				.weight = 10,
				.net = {
					.ipv6 = {
						.address = {
							.x = {
								htons(0xfe80), htons(0x0000), htons(0x0000), htons(0x0000),
								htons(0x16dd), htons(0xa9ff), htons(0xfe7e), htons(0xb4c2),
							}
						},
						.prefixlength = 64,
					},
				},
			},
		},
		{
			.text = "57:04:13:01:f9:26#60",
			.data = {
				.type = SUBNET_MAC,
				.weight = 60,
				.net = {
					.mac = {
						.address = {
							.x = {0x57, 0x04, 0x13, 0x01, 0xf9, 0x26},
						},
					},
				},
			},
		},
	};

	for(size_t i = 0; i < sizeof(testcases) / sizeof(*testcases); ++i) {
		const char *text = testcases[i].text;
		const subnet_t *ref = &testcases[i].data;

		subnet_t sub = {0};
		bool ok = str2net(&sub, text);

		// Split into separate assertions for more clear failures
		assert_true(ok);
		assert_int_equal(ref->type, sub.type);
		assert_int_equal(ref->weight, sub.weight);

		switch(ref->type) {
		case SUBNET_MAC:
			assert_memory_equal(&ref->net.mac.address, &sub.net.mac.address, sizeof(mac_t));
			break;

		case SUBNET_IPV4:
			assert_int_equal(ref->net.ipv4.prefixlength, sub.net.ipv4.prefixlength);
			assert_memory_equal(&ref->net.ipv4.address, &sub.net.ipv4.address, sizeof(ipv4_t));
			break;

		case SUBNET_IPV6:
			assert_int_equal(ref->net.ipv6.prefixlength, sub.net.ipv6.prefixlength);
			assert_memory_equal(&ref->net.ipv6.address, &sub.net.ipv6.address, sizeof(ipv6_t));
			break;

		default:
			fail_msg("unknown subnet type %d", ref->type);
		}
	}
}

static void test_str2net_invalid(void **state) {
	(void)state;

	subnet_t sub = {0};

	const char *test_cases[] = {
		// Overflow
		"1.2.256.0",

		// Invalid mask
		"1.2.3.0/",
		"1.2.3.0/42",
		"1.2.3.0/MASK",
		"fe80::/129",
		"fe80::/MASK",
		"cb:0c:1b:60:ed:7a/1",

		// Invalid weight
		"1.2.3.4#WEIGHT",
		"1.2.0.0/16#WEIGHT",
		"1.2.0.0/16#",
		"feff::/16#",
		"feff::/16#w",

		NULL,
	};

	for(const char **str = test_cases; *str; ++str) {
		bool ok = str2net(&sub, *str);
		assert_false(ok);
	}
}

static void test_net2str_valid(void **state) {
	(void)state;

	const net_str_testcase testcases[] = {
		{
			.text = "12:fe:ff:3a:28:90#42",
			.data = {
				.type = SUBNET_MAC,
				.weight = 42,
				.net = {
					.mac = {
						.address = {
							.x = {0x12, 0xfe, 0xff, 0x3a, 0x28, 0x90}
						},
					},
				},
			},
		},
		{
			.text = "1.2.3.4",
			.data = {
				.type = SUBNET_IPV4,
				.weight = 10,
				.net = {
					.ipv4 = {
						.address = {
							.x = {1, 2, 3, 4}
						},
						.prefixlength = 32,
					},
				},
			},
		},
		{
			.text = "181.35.16.0/27#1",
			.data = {
				.type = SUBNET_IPV4,
				.weight = 1,
				.net = {
					.ipv4 = {
						.address = {
							.x = {181, 35, 16, 0}
						},
						.prefixlength = 27,
					},
				},
			},
		},
		{
			.text = "5fbf:5cfe:0:fdd2:fd76::/96#900",
			.data = {
				.type = SUBNET_IPV6,
				.weight = 900,
				.net = {
					.ipv6 = {
						.address = {
							.x = {
								htons(0x5fbf), htons(0x5cfe), htons(0x0000), htons(0xfdd2),
								htons(0xfd76), htons(0x0000), htons(0x0000), htons(0x0000),
							},
						},
						.prefixlength = 96,
					},
				},
			},
		},
	};

	for(size_t i = 0; i < sizeof(testcases) / sizeof(*testcases); ++i) {
		const char *text = testcases[i].text;
		const subnet_t *ref = &testcases[i].data;

		char buf[256];
		bool ok = net2str(buf, sizeof(buf), ref);

		assert_true(ok);
		assert_string_equal(text, buf);
	}
}

static void test_net2str_invalid(void **state) {
	(void)state;

	const subnet_t sub = {0};
	char buf[256];
	assert_false(net2str(NULL, sizeof(buf), &sub));
	assert_false(net2str(buf, sizeof(buf), NULL));
}

static void test_maskcheck_valid_ipv4(void **state) {
	(void)state;

	const ipv4_t a = {{10, 0, 0, 0}};
	const ipv4_t b = {{192, 168, 0, 0}};
	const ipv4_t c = {{192, 168, 24, 0}};

	assert_true(maskcheck(&a, 8, sizeof(a)));
	assert_true(maskcheck(&b, 16, sizeof(b)));
	assert_true(maskcheck(&c, 24, sizeof(c)));
}

static void test_maskcheck_valid_ipv6(void **state) {
	(void)state;

	const ipv6_t a = {{10, 0, 0, 0, 0, 0, 0, 0}};
	assert_true(maskcheck(&a, 8, sizeof(a)));

	const ipv6_t b = {{10, 20, 0, 0, 0, 0, 0, 0}};
	assert_true(maskcheck(&b, 32, sizeof(b)));

	const ipv6_t c = {{192, 168, 24, 0, 0, 0, 0, 0}};
	assert_true(maskcheck(&c, 48, sizeof(c)));
}

static void test_maskcheck_invalid_ipv4(void **state) {
	(void)state;

	const ipv4_t a = {{10, 20, 0, 0}};
	const ipv4_t b = {{10, 20, 30, 0}};

	assert_false(maskcheck(&a, 8, sizeof(a)));
	assert_false(maskcheck(&b, 16, sizeof(b)));
}

static void test_maskcheck_invalid_ipv6(void **state) {
	(void)state;

	const ipv6_t a = {{1, 2, 3, 4, 5, 6, 7, 0xAABB}};

	for(int mask = 0; mask < 128; mask += 8) {
		assert_false(maskcheck(&a, mask, sizeof(a)));
	}
}

int main(void) {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_maskcmp),
		cmocka_unit_test(test_mask),
		cmocka_unit_test(test_maskcpy),

		cmocka_unit_test(test_subnet_compare_different_types),

		cmocka_unit_test(test_subnet_compare_mac_eq),
		cmocka_unit_test(test_subnet_compare_mac_neq_address),
		cmocka_unit_test(test_subnet_compare_mac_weight),
		cmocka_unit_test(test_subnet_compare_mac_owners),

		cmocka_unit_test(test_subnet_compare_ipv4_eq),
		cmocka_unit_test(test_subnet_compare_ipv4_neq),
		cmocka_unit_test(test_subnet_compare_ipv4_weight),
		cmocka_unit_test(test_subnet_compare_ipv4_owners),

		cmocka_unit_test(test_subnet_compare_ipv6_eq),
		cmocka_unit_test(test_subnet_compare_ipv6_neq),
		cmocka_unit_test(test_subnet_compare_ipv6_weight),
		cmocka_unit_test(test_subnet_compare_ipv6_owners),

		cmocka_unit_test(test_str2net_valid),
		cmocka_unit_test(test_str2net_invalid),

		cmocka_unit_test(test_net2str_valid),
		cmocka_unit_test(test_net2str_invalid),

		cmocka_unit_test(test_maskcheck_valid_ipv4),
		cmocka_unit_test(test_maskcheck_valid_ipv6),
		cmocka_unit_test(test_maskcheck_invalid_ipv4),
		cmocka_unit_test(test_maskcheck_invalid_ipv6),
	};
	return cmocka_run_group_tests(tests, NULL, NULL);
}
