#include "unittest.h"
#include "../../src/net.h"
#include "../../src/script.h"

static environment_t *device_env = NULL;

// silence -Wmissing-prototypes
void __wrap_environment_init(environment_t *env);
void __wrap_environment_exit(environment_t *env);
bool __wrap_execute_script(const char *name, environment_t *env);

void __wrap_environment_init(environment_t *env) {
	assert_non_null(env);
	assert_null(device_env);
	device_env = env;
}

void __wrap_environment_exit(environment_t *env) {
	assert_ptr_equal(device_env, env);
	device_env = NULL;
}

bool __wrap_execute_script(const char *name, environment_t *env) {
	(void)env;

	check_expected_ptr(name);

	// Used instead of mock_type(bool) to silence clang warning
	return mock() ? true : false;
}

static void run_device_enable_disable(void (*device_func)(void),
                                      const char *script) {
	expect_string(__wrap_execute_script, name, script);
	will_return(__wrap_execute_script, true);

	device_func();
}

static void test_device_enable_calls_tinc_up(void **state) {
	(void)state;

	run_device_enable_disable(&device_enable, "tinc-up");
}

static void test_device_disable_calls_tinc_down(void **state) {
	(void)state;

	run_device_enable_disable(&device_disable, "tinc-down");
}

int main(void) {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_device_enable_calls_tinc_up),
		cmocka_unit_test(test_device_disable_calls_tinc_down),
	};
	return cmocka_run_group_tests(tests, NULL, NULL);
}
