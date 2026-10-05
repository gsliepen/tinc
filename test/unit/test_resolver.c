#include "unittest.h"
#include "../../src/event.h"
#include "../../src/resolver.h"

// getaddrinfo() is replaced by the fake in fake_getaddrinfo.c.

static uint16_t port_of(const struct addrinfo *ai) {
	return ntohs(((const struct sockaddr_in *)ai->ai_addr)->sin_port);
}

// Ends the event loop if a test gets stuck.
static timeout_t watchdog;
static bool timed_out;

static void watchdog_expired(void *data) {
	(void)data;
	timed_out = true;
	event_exit();
}

static void run_event_loop(void) {
	timeout_add(&watchdog, watchdog_expired, NULL, &(struct timeval) {
		10, 0
	});
	assert_true(event_loop());
	timeout_del(&watchdog);
	assert_false(timed_out);
}

typedef struct result_t {
	int calls;
	struct addrinfo *ai;
} result_t;

static void store_and_exit(void *data, struct addrinfo *ai) {
	result_t *result = data;
	result->calls++;
	result->ai = ai;
	event_exit();
}

static void record_call(void *data, struct addrinfo *ai) {
	result_t *result = data;
	result->calls++;
	result->ai = ai;
}

static void test_resolve_numeric(void **state) {
	(void)state;

	struct addrinfo *ai = resolve_numeric("127.0.0.1", "655", SOCK_STREAM);
	assert_non_null(ai);
	assert_int_equal(655, port_of(ai));
	freeaddrinfo(ai);

	assert_null(resolve_numeric("slow-0.test", "655", SOCK_STREAM));
	assert_null(resolve_numeric("127.0.0.1", "tinc", SOCK_STREAM));
}

static void test_resolve_calls_back_later(void **state) {
	(void)state;

	result_t result = {0};
	assert_non_null(resolve_start("slow-0.test", "655", SOCK_STREAM, store_and_exit, &result));
	assert_int_equal(0, result.calls);

	run_event_loop();

	assert_int_equal(1, result.calls);
	assert_non_null(result.ai);
	assert_int_equal(655, port_of(result.ai));
	freeaddrinfo(result.ai);
}

static void test_resolve_failure(void **state) {
	(void)state;

	result_t result = {0};
	assert_non_null(resolve_start("fail-0.test", "655", SOCK_STREAM, store_and_exit, &result));

	run_event_loop();

	assert_int_equal(1, result.calls);
	assert_null(result.ai);
}

static int ticks;
static timeout_t ticker;

static void tick(void *data) {
	(void)data;
	ticks++;
	timeout_set(&ticker, &(struct timeval) {
		0, 10000
	});
}

static void test_slow_lookup_does_not_block_event_loop(void **state) {
	(void)state;

	ticks = 0;
	timeout_add(&ticker, tick, NULL, &(struct timeval) {
		0, 10000
	});

	result_t result = {0};
	assert_non_null(resolve_start("slow-300.test", "655", SOCK_STREAM, store_and_exit, &result));

	run_event_loop();
	timeout_del(&ticker);

	assert_int_equal(1, result.calls);
	freeaddrinfo(result.ai);

	// A blocked loop would not tick at all; an unloaded one ticks about 30 times.
	assert_true(ticks >= 10);
}

static void test_cancelled_lookup_does_not_call_back(void **state) {
	(void)state;

	result_t cancelled_result = {0};
	resolve_t *cancelled = resolve_start("slow-10.test", "655", SOCK_STREAM, record_call, &cancelled_result);
	assert_non_null(cancelled);
	resolve_cancel(cancelled);

	// Outlives the cancelled lookup, so that its completion gets processed.
	result_t result = {0};
	assert_non_null(resolve_start("slow-100.test", "655", SOCK_STREAM, store_and_exit, &result));

	run_event_loop();

	assert_int_equal(0, cancelled_result.calls);
	assert_int_equal(1, result.calls);
	freeaddrinfo(result.ai);
}

/*
    Property: among many concurrent lookups with random latency and outcome,
    some cancelled up front and some cancelled from other callbacks, and some
    starting further lookups from their callback, every lookup that is not
    cancelled calls back exactly once with its own result, and no cancelled
    lookup ever calls back. Set TINC_TEST_SEED to replay a failing run.
*/

#define JOBS 48

typedef struct job_t {
	int index;
	resolve_t *request;
	bool fail;
	bool chain;
	bool cancelled;
	int calls;
} job_t;

// The first half are started by the test, the second half by chaining callbacks.
static job_t jobs[2 * JOBS];
static int calls;
static int expected_calls;

static void job_done(void *data, struct addrinfo *ai);
static void finish_round(void);

static void start_job(job_t *job) {
	char host[32], service[8];
	snprintf(host, sizeof(host), "%s-%d.test", job->fail ? "fail" : "slow", rand() % 30);
	snprintf(service, sizeof(service), "%d", 1000 + job->index);

	job->request = resolve_start(host, service, SOCK_STREAM, job_done, job);
	assert_non_null(job->request);
}

static void cancel_job(job_t *job) {
	resolve_cancel(job->request);
	job->cancelled = true;
	expected_calls -= 1 + job->chain;
}

static job_t *pick_pending_job(void) {
	job_t *job = &jobs[rand() % JOBS];
	return job->calls || job->cancelled ? NULL : job;
}

static void job_done(void *data, struct addrinfo *ai) {
	job_t *job = data;

	assert_false(job->cancelled);
	job->calls++;
	calls++;

	if(job->fail) {
		assert_null(ai);
	} else {
		assert_non_null(ai);
		assert_int_equal(1000 + job->index, port_of(ai));
		freeaddrinfo(ai);
	}

	if(job->chain) {
		start_job(&jobs[job->index + JOBS]);
	}

	if(rand() % 4 == 0) {
		job_t *victim = pick_pending_job();

		if(victim && victim != job) {
			cancel_job(victim);
		}
	}

	if(calls == expected_calls) {
		finish_round();
	}
}

static unsigned int seed;
static unsigned int rounds_left;

static void start_round(void) {
	print_message("seed %u\n", seed);
	srand(seed++);
	memset(jobs, 0, sizeof(jobs));
	calls = 0;
	expected_calls = 0;

	for(int i = 0; i < 2 * JOBS; i++) {
		jobs[i].index = i;
		jobs[i].fail = rand() % 4 == 0;
	}

	for(int i = 0; i < JOBS; i++) {
		jobs[i].chain = rand() % 4 == 0;
		expected_calls += 1 + jobs[i].chain;
		start_job(&jobs[i]);
	}

	for(int i = 0; i < JOBS; i++) {
		if(rand() % 6 == 0) {
			cancel_job(&jobs[i]);
		}
	}
}

static void finish_round(void) {
	for(int i = 0; i < 2 * JOBS; i++) {
		bool started = i < JOBS || (jobs[i - JOBS].chain && jobs[i - JOBS].calls);

		if(jobs[i].cancelled || !started) {
			assert_int_equal(0, jobs[i].calls);
		} else {
			assert_int_equal(1, jobs[i].calls);
		}
	}

	if(--rounds_left) {
		start_round();
	} else {
		event_exit();
	}
}

static void test_concurrent_lookups(void **state) {
	(void)state;

	const char *env = getenv("TINC_TEST_SEED");
	seed = env ? (unsigned int)strtoul(env, NULL, 10) : (unsigned int)time(NULL);
	rounds_left = 8;

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
		cmocka_unit_test(test_resolve_numeric),
		cmocka_unit_test(test_resolve_calls_back_later),
		cmocka_unit_test(test_resolve_failure),
		cmocka_unit_test(test_slow_lookup_does_not_block_event_loop),
		cmocka_unit_test(test_cancelled_lookup_does_not_call_back),
		cmocka_unit_test(test_concurrent_lookups),
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}
