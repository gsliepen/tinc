#ifndef __TINC_LOGGER_H__

#include <syslog.h>
#include <stdarg.h>

enum {
	DEBUG_NOTHING = 0,			/* Quiet mode, only show starting/stopping of the daemon */
	DEBUG_ALWAYS = 0,
	DEBUG_CONNECTIONS = 1,		/* Show (dis)connects of other tinc daemons via TCP */
	DEBUG_ERROR = 2,			/* Show error messages received from other hosts */
	DEBUG_STATUS = 2,			/* Show status messages received from other hosts */
	DEBUG_PROTOCOL = 3,			/* Show the requests that are sent/received */
	DEBUG_META = 4,				/* Show contents of every request that is sent/received */
	DEBUG_TRAFFIC = 5,			/* Show network traffic information */
	DEBUG_PACKET = 6,			/* Show contents of each packet that is being sent/received */
	DEBUG_SCARY_THINGS = 10		/* You have been warned */
};

enum {
	LOGMODE_NULL,
	LOGMODE_STDERR,
	LOGMODE_FILE,
	LOGMODE_SYSLOG
};

extern volatile int debug_level;
extern void openlogger(const char *, int);
extern void vlogger(int, const char *, va_list ap);
extern void closelogger(void);

/* Inline logger function because it's used quite often */

static inline void logger(int level, int priority, const char *format, ...) {
	va_list ap;

	if(level == DEBUG_ALWAYS || debug_level >= level) {
		va_start(ap, format);
		vlogger(priority, format, ap);
		va_end(ap);
	}
}

#endif /* __TINC_LOGGER_H__ */
