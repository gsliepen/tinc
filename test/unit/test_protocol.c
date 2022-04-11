#include "unittest.h"
#include "../../src/protocol.h"

static void test_get_invalid_request(void **state) {
	(void)state;

	assert_null(get_request_entry(ALL));
	assert_null(get_request_entry(LAST));
}

static void test_get_valid_request_returns_nonnull(void **state) {
	(void)state;

	for(request_t req = ID; req < LAST; ++req) {
		const request_entry_t *ent = get_request_entry(req);
		assert_non_null(ent);
		assert_non_null(ent->name);
	}
}

int main(void) {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_get_invalid_request),
		cmocka_unit_test(test_get_valid_request_returns_nonnull),
	};
	return cmocka_run_group_tests(tests, NULL, NULL);
}
