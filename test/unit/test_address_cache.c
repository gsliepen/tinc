#include "unittest.h"
#include "../../src/address_cache.h"
#include "../../src/event.h"
#include "../../src/names.h"
#include "../../src/node.h"

// getaddrinfo() is replaced by the fake in fake_getaddrinfo.c.

/*
    The driver plays the part of an outgoing connection: it asks the cache for
    addresses one by one, holding each for a while as if connecting to it, and
    stops when the cache is waiting for a lookup, until retry_outgoing_now()
    wakes it up. It ends the event loop once the cache runs out of addresses.
*/

static struct {
	address_cache_t *cache;
	unsigned int hold_ms;
	timeout_t timer;
	int ports[16];
	int count;
	int waits;
	int wakeups;
	void (*finished)(void);
} driver;

static void drive(void *data);

static timeout_t nudge;

static void do_nothing(void *data) {
	(void)data;
}

// The event loop notices event_exit() only after its next wait, which a timer callback does not shorten.
static void exit_event_loop(void) {
	event_exit();
	timeout_add(&nudge, do_nothing, NULL, &(struct timeval) {
		0, 0
	});
}

static void drive_after(unsigned int ms) {
	timeout_add(&driver.timer, drive, NULL, &(struct timeval) {
		ms / 1000, (ms % 1000) * 1000
	});
}

void __wrap_retry_outgoing_now(const node_t *n);

void __wrap_retry_outgoing_now(const node_t *n) {
	(void)n;
	driver.wakeups++;
	drive_after(0);
}

static void drive(void *data) {
	(void)data;
	const sockaddr_t *sa = get_recent_address(driver.cache);

	if(sa) {
		assert_true(driver.count < 16);
		driver.ports[driver.count++] = ntohs(sa->in.sin_port);
		drive_after(driver.hold_ms);
	} else if(driver.cache->waiting) {
		driver.waits++;
	} else {
		timeout_del(&driver.timer);
		driver.finished();
	}
}


// Ends the event loop if a test gets stuck.
static timeout_t watchdog;
static bool timed_out;

static void watchdog_expired(void *data) {
	(void)data;
	timed_out = true;
	exit_event_loop();
}

static void run_event_loop(void) {
	timeout_add(&watchdog, watchdog_expired, NULL, &(struct timeval) {
		10, 0
	});
	assert_true(event_loop());
	timeout_del(&watchdog);
	assert_false(timed_out);
}

static node_t *node;
static char hosts_file[PATH_MAX];

static void write_addresses(const char *addresses) {
	FILE *f = fopen(hosts_file, "w");
	assert_non_null(f);
	fputs(addresses, f);
	fclose(f);
}

static address_cache_t *open_cache_with(const char *addresses) {
	write_addresses(addresses);
	return open_address_cache(node);
}

static int setup(void **state) {
	(void)state;

	static char dir[] = "/tmp/tinc_address_cache_XXXXXX";

	if(!mkdtemp(dir)) {
		return -1;
	}

	confbase = dir;
	char hosts_dir[sizeof(dir) + 8];
	snprintf(hosts_dir, sizeof(hosts_dir), "%s/hosts", dir);

	if(mkdir(hosts_dir, 0700)) {
		return -1;
	}

	snprintf(hosts_file, sizeof(hosts_file), "%s/hosts/test", dir);
	node = new_node("test");
	return 0;
}

static int teardown(void **state) {
	(void)state;

	unlink(hosts_file);
	*strrchr(hosts_file, '/') = 0;
	rmdir(hosts_file);
	rmdir(confbase);
	free_node(node);
	return 0;
}

// Runs the driver over all addresses of the cache.
static void collect_addresses(address_cache_t *cache, unsigned int hold_ms) {
	memset(&driver, 0, sizeof(driver));
	driver.cache = cache;
	driver.hold_ms = hold_ms;
	driver.finished = exit_event_loop;

	drive_after(0);
	run_event_loop();

	// Every wait ends with exactly one wakeup, and nothing else wakes the driver.
	assert_int_equal(driver.waits, driver.wakeups);
}

static void test_numeric_addresses_need_no_waiting(void **state) {
	(void)state;

	address_cache_t *cache = open_cache_with(
	                                 "Address = 127.0.0.1 1001\n"
	                                 "Address = 127.0.0.1 1002\n");

	collect_addresses(cache, 0);

	assert_int_equal(2, driver.count);
	assert_int_equal(1001, driver.ports[0]);
	assert_int_equal(1002, driver.ports[1]);
	assert_int_equal(0, driver.waits);

	close_address_cache(cache);
}

static void test_lookups_run_in_parallel(void **state) {
	(void)state;

	address_cache_t *cache = open_cache_with(
	                                 "Address = slow-300.test 1001\n"
	                                 "Address = slow-300.test 1002\n"
	                                 "Address = slow-300.test 1003\n");

	struct timeval start, end, elapsed;
	gettimeofday(&start, NULL);
	collect_addresses(cache, 0);
	gettimeofday(&end, NULL);
	timersub(&end, &start, &elapsed);

	assert_int_equal(3, driver.count);
	assert_int_equal(1001, driver.ports[0]);
	assert_int_equal(1002, driver.ports[1]);
	assert_int_equal(1003, driver.ports[2]);

	// One after the other, the lookups would take 900 ms.
	assert_true(elapsed.tv_sec == 0 && elapsed.tv_usec < 600000);

	close_address_cache(cache);
}

static void test_order_of_address_statements_is_kept(void **state) {
	(void)state;

	address_cache_t *cache = open_cache_with(
	                                 "Address = slow-200.test 1001\n"
	                                 "Address = slow-0.test 1002\n"
	                                 "Address = 127.0.0.1 1003\n");

	collect_addresses(cache, 0);

	assert_int_equal(3, driver.count);
	assert_int_equal(1001, driver.ports[0]);
	assert_int_equal(1002, driver.ports[1]);
	assert_int_equal(1003, driver.ports[2]);

	close_address_cache(cache);
}

static void test_failed_lookups_are_skipped(void **state) {
	(void)state;

	address_cache_t *cache = open_cache_with(
	                                 "Address = fail-0.test 1001\n"
	                                 "Address = slow-0.test 1002\n"
	                                 "Address = fail-100.test 1003\n");

	collect_addresses(cache, 0);

	assert_int_equal(1, driver.count);
	assert_int_equal(1002, driver.ports[0]);

	close_address_cache(cache);
}

static void test_lookup_completing_during_connection_attempt_does_not_wake(void **state) {
	(void)state;

	// The second lookup completes while the first address is being tried.
	address_cache_t *cache = open_cache_with(
	                                 "Address = slow-0.test 1001\n"
	                                 "Address = slow-100.test 1002\n");

	collect_addresses(cache, 300);

	assert_int_equal(2, driver.count);
	assert_int_equal(1001, driver.ports[0]);
	assert_int_equal(1002, driver.ports[1]);

	close_address_cache(cache);
}

static void end_wait(void *data) {
	(void)data;
	exit_event_loop();
}

static void test_reset_cancels_pending_lookups(void **state) {
	(void)state;

	address_cache_t *cache = open_cache_with("Address = slow-100.test 1001\n");
	memset(&driver, 0, sizeof(driver));

	assert_null(get_recent_address(cache));
	assert_true(cache->waiting);
	reset_address_cache(cache);
	assert_false(cache->waiting);

	// Leave the cancelled lookup enough time to complete.
	timeout_add(&driver.timer, end_wait, NULL, &(struct timeval) {
		0, 300000
	});
	run_event_loop();

	assert_int_equal(0, driver.wakeups);
	close_address_cache(cache);
}

/*
    Property: with any mix of numeric, slow and failing Address statements,
    and any time spent on each address, the cache yields the addresses of the
    successful statements in configuration order, and wakes up a waiting
    connection exactly once per wait. Set TINC_TEST_SEED to replay a failing run.
*/

#define MAX_STATEMENTS 8

static unsigned int seed;
static unsigned int rounds_left;
static int expected_ports[MAX_STATEMENTS];
static int expected_count;

static void start_round(void) {
	print_message("seed %u\n", seed);
	srand(seed++);

	char addresses[MAX_STATEMENTS * 64] = "";
	int statements = 1 + rand() % MAX_STATEMENTS;
	expected_count = 0;

	for(int i = 0; i < statements; i++) {
		int port = 1001 + i;
		char line[64];

		switch(rand() % 3) {
		case 0:
			snprintf(line, sizeof(line), "Address = 127.0.0.1 %d\n", port);
			expected_ports[expected_count++] = port;
			break;

		case 1:
			snprintf(line, sizeof(line), "Address = slow-%d.test %d\n", rand() % 50, port);
			expected_ports[expected_count++] = port;
			break;

		default:
			snprintf(line, sizeof(line), "Address = fail-%d.test %d\n", rand() % 50, port);
			break;
		}

		strncat(addresses, line, sizeof(addresses) - strlen(addresses) - 1);
	}

	driver.cache = open_cache_with(addresses);
	driver.hold_ms = rand() % 20;
	drive_after(0);
}

static void finish_round(void) {
	assert_int_equal(driver.waits, driver.wakeups);
	assert_int_equal(expected_count, driver.count);

	for(int i = 0; i < expected_count; i++) {
		assert_int_equal(expected_ports[i], driver.ports[i]);
	}

	close_address_cache(driver.cache);
	memset(&driver, 0, sizeof(driver));
	driver.finished = finish_round;

	if(--rounds_left) {
		start_round();
	} else {
		exit_event_loop();
	}
}

static void test_any_address_statements(void **state) {
	(void)state;

	const char *env = getenv("TINC_TEST_SEED");
	seed = env ? (unsigned int)strtoul(env, NULL, 10) : (unsigned int)time(NULL);
	rounds_left = 16;

	memset(&driver, 0, sizeof(driver));
	driver.finished = finish_round;
	start_round();
	run_event_loop();

	assert_int_equal(0, rounds_left);
}

// The event loop cannot be restarted once it exits, so each test needs a separate process.
int main(int argc, char *argv[]) {
	if(argc > 1) {
		cmocka_set_test_filter(argv[1]);
	}

	const struct CMUnitTest tests[] = {
		cmocka_unit_test_setup_teardown(test_numeric_addresses_need_no_waiting, setup, teardown),
		cmocka_unit_test_setup_teardown(test_lookups_run_in_parallel, setup, teardown),
		cmocka_unit_test_setup_teardown(test_order_of_address_statements_is_kept, setup, teardown),
		cmocka_unit_test_setup_teardown(test_failed_lookups_are_skipped, setup, teardown),
		cmocka_unit_test_setup_teardown(test_lookup_completing_during_connection_attempt_does_not_wake, setup, teardown),
		cmocka_unit_test_setup_teardown(test_reset_cancels_pending_lookups, setup, teardown),
		cmocka_unit_test_setup_teardown(test_any_address_statements, setup, teardown),
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}
