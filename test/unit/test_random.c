#include "unittest.h"
#include "../../src/random.h"
#include "../../src/xalloc.h"

static int setup(void **state) {
	(void)state;
	random_init();
	return 0;
}

static int teardown(void **state) {
	(void)state;
	random_exit();
	return 0;
}

#define zerolen 128
static const uint8_t zero[zerolen] = {0};

static void test_randomize_zero_must_not_change_memory(void **state) {
	(void)state;

	uint8_t buf[zerolen] = {0};
	randomize(buf, 0);

	assert_memory_equal(zero, buf, sizeof(buf));
}

static void test_randomize_does_not_overflow(void **state) {
	(void)state;

	uint8_t buf[zerolen] = {0};
	const size_t half = sizeof(buf) / 2;
	randomize(buf, half);

	assert_memory_not_equal(zero, buf, half);
	assert_memory_equal(zero, &buf[half], half);
}

static void test_randomize_full_changes_memory(void **state) {
	(void)state;

	uint8_t buf[zerolen] = {0};
	randomize(buf, sizeof(buf));

	assert_memory_not_equal(zero, buf, sizeof(buf));
}

static void test_randomize_does_not_repeat(void **state) {
	(void)state;

	// Ask randomize() for small chunks so there's more
	// chance for it to repeat itself (within reason).
#define chunklen 16

	const size_t chunks = 1024;
	uint8_t (*buffers)[chunklen] = xzalloc(chunks * chunklen);

	// Fill buffers with (hopefully) random data
	for(size_t i = 0; i < chunks; ++i) {
		randomize(buffers[i], chunklen);

		// Check there was no overflow to the right
		if(i < chunks - 1) {
			assert_memory_equal(zero, buffers[i + 1], chunklen);
		}
	}

	// Check there were no repetitions (with 128-bit buffers collisions are very unlikely)
	for(size_t i = 0; i < chunks - 1; ++i) {
		for(size_t j = i + 1; j < chunks; ++j) {
			assert_memory_not_equal(buffers[i], buffers[j], chunklen);
		}
	}

	free(buffers);
#undef chunklen
}

int main(void) {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_randomize_zero_must_not_change_memory),
		cmocka_unit_test(test_randomize_does_not_overflow),
		cmocka_unit_test(test_randomize_full_changes_memory),
		cmocka_unit_test(test_randomize_does_not_repeat),
	};
	return cmocka_run_group_tests(tests, setup, teardown);
}
