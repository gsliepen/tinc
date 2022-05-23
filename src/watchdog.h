#ifndef TINC_WATCHDOG_H
#define TINC_WATCHDOG_H

// Start sending keepalive notifications to watchdog.
// Called after initialization is finished before entering the event loop.
void watchdog_start(void);

// Stop sending keepalive notifications.
// Called shortly before exiting.
void watchdog_stop(void);

// Send keepalive notification.
void watchdog_ping(void);

#endif // TINC_WATCHDOG_H
