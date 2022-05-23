#include "../system.h"

#include <systemd/sd-daemon.h>

#include "../event.h"
#include "../logger.h"
#include "../watchdog.h"

static timeout_t timer;
static struct timeval interval;

static uint64_t second_to_microsecond(time_t second) {
	return second * 1000000;
}

static time_t microsecond_to_second(uint64_t micros) {
	return (time_t)(micros / 1000000);
}

// Ignore errors from sd_notify() since there's nothing we can do if it breaks anyway.
// Also, there's this passage in `man sd_notify.3`:
//     In order to support both service managers that implement this scheme and those
//     which do not, it is generally recommended to ignore the return value of this call.
void watchdog_ping(void) {
	sd_notify(false, "WATCHDOG=1");
}

static void watchdog_handler(void *data) {
	(void)data;
	watchdog_ping();
	timeout_set(&timer, &interval);
}

static bool watchdog_register(void) {
	uint64_t timeout = 0;

	if(sd_watchdog_enabled(false, &timeout) <= 0 || !timeout) {
		return false;
	}

	if(timeout < second_to_microsecond(2)) {
		logger(DEBUG_ALWAYS, LOG_WARNING, "Consider using a higher watchdog timeout. Spurious failures may occur.");
	}

	// Send notifications twice per timeout period
	timeout /= 2;

	interval.tv_sec = microsecond_to_second(timeout);

	if(interval.tv_sec) {
		timeout -= second_to_microsecond(interval.tv_sec);
	}

	interval.tv_usec = (suseconds_t)timeout;

	timeout_add(&timer, watchdog_handler, &timer, &interval);
	watchdog_ping();

	return true;
}

void watchdog_start(void) {
	sd_notify(false, "READY=1");
	bool enabled = watchdog_register();
	logger(DEBUG_ALWAYS, LOG_INFO, "Watchdog %s", enabled ? "started" : "is disabled");
}

void watchdog_stop(void) {
	sd_notify(false, "STOPPING=1");
	timeout_del(&timer);
}
