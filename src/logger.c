/*
    logger.c -- logging code
    Copyright (C) 2004-2022 Guus Sliepen <guus@tinc-vpn.org>
                  2004-2005 Ivo Timmermans

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/

#include "system.h"

#include "conf.h"
#include "meta.h"
#include "names.h"
#include "logger.h"
#include "connection.h"
#include "control_common.h"
#include "process.h"
#include "sptps.h"
#include "console.h"

debug_t debug_level = DEBUG_NOTHING;
static logmode_t logmode = LOGMODE_STDERR;
static pid_t logpid;
static FILE *logfile = NULL;
#ifdef HAVE_WINDOWS
static HANDLE loghandle = NULL;
#endif
static const char *logident = NULL;
static bool colorize_stderr = false;
bool logcontrol = false; // controlled by REQ_LOG <level>
int umbilical = 0;
bool umbilical_colorize = false;

#define SGR(s) ("\x1b[" s "m")

typedef enum color_t {
	RED, GREEN, YELLOW, BLUE, MAGENTA, CYAN, WHITE, GRAY,
	RESET, // not really a color
} color_t;

typedef struct priority_disp_t {
	const char *name;
	color_t color;
} priority_disp_t;

static const priority_disp_t priorities[] = {
	[LOG_EMERG]   = {"EMERGENCY", MAGENTA},
	[LOG_ALERT]   = {"ALERT",     MAGENTA},
	[LOG_CRIT]    = {"CRITICAL",  MAGENTA},
	[LOG_ERR]     = {"ERROR",     RED},
	[LOG_WARNING] = {"WARNING",   YELLOW},
	[LOG_NOTICE]  = {"NOTICE",    CYAN},
	[LOG_INFO]    = {"INFO",      GREEN},
	[LOG_DEBUG]   = {"DEBUG",     BLUE},
};

static const char *ansi_codes[] = {
	[RED]     = SGR("31;1"),
	[GREEN]   = SGR("32;1"),
	[YELLOW]  = SGR("33;1"),
	[BLUE]    = SGR("34;1"),
	[MAGENTA] = SGR("35;1"),
	[CYAN]    = SGR("36;1"),
	[WHITE]   = SGR("37;1"),
	[GRAY]    = SGR("90"),
	[RESET]   = SGR("0"),
};

static priority_disp_t get_priority(int priority) {
	static const priority_disp_t unknown = {"UNKNOWN", WHITE};

	if(priority >= LOG_EMERG && priority <= LOG_DEBUG) {
		return priorities[priority];
	} else {
		return unknown;
	}
}

// Formats current time to the second.
// Reuses result so repeated calls within the same second are more efficient.
static const char *current_time_str(void) {
	static char timestr[sizeof("2000-12-31 12:34:56")] = "";
	static time_t last_time = 0;

	if(!now.tv_sec) {
		gettimeofday(&now, NULL);
	}

	time_t now_sec = now.tv_sec;

	if(!*timestr || now_sec != last_time) {
		last_time = now_sec;
		strftime(timestr, sizeof(timestr), "%Y-%m-%d %H:%M:%S", localtime(&now_sec));
	}

	return timestr;
}

// Format log entry with time, log level, and (possibly) colors, remembering if it was colorized.
// Returns true if buffer has been changed.
static bool format_pretty(char *buf, size_t buflen, int prio, const char *message, bool colorize, bool *colorized) {
	// If we already wrote to buffer, and its colorization matches, we're done here
	if(*buf && colorize == *colorized) {
		return false;
	}

	// Otherwise, remember current colorization for future comparisons
	*colorized = colorize;

	priority_disp_t priority = get_priority(prio);
	const char *color = "", *reset = "", *timecol = "";

	if(colorize) {
		color = ansi_codes[priority.color];
		reset = ansi_codes[RESET];
		timecol = ansi_codes[GRAY];
	}

	const char *timestr = current_time_str();
	snprintf(buf, buflen, "%s%s %s%-7s%s %s", timecol, timestr, color, priority.name, reset, message);
	return true;
}

static bool should_log(debug_t level) {
	return (level <= debug_level && logmode != LOGMODE_NULL) || logcontrol;
}

static void real_logger(debug_t level, int priority, const char *message) {
	char pretty[1024] = "";
	bool pretty_colorized = false;
	static bool suppress = false;

	if(suppress) {
		return;
	}

	if(level <= debug_level) {
		switch(logmode) {
		case LOGMODE_STDERR:
			format_pretty(pretty, sizeof(pretty), priority, message, colorize_stderr, &pretty_colorized);
			fprintf(stderr, "%s\n", pretty);
			fflush(stderr);
			break;

		case LOGMODE_FILE: {
			const char *timestr = current_time_str();
			fprintf(logfile, "%s %s[%ld]: %s\n", timestr, logident, (long)logpid, message);
			fflush(logfile);
			break;
		}

		case LOGMODE_SYSLOG:
#ifdef HAVE_WINDOWS
			{
				const char *messages[] = {message};
				ReportEvent(loghandle, priority, 0, 0, NULL, 1, 0, messages, NULL);
			}

#else
#ifdef HAVE_SYSLOG_H
			syslog(priority, "%s", message);
#endif
#endif
			break;

		case LOGMODE_NULL:
		default:
			break;
		}

		if(umbilical && do_detach) {
			format_pretty(pretty, sizeof(pretty), priority, message, umbilical_colorize, &pretty_colorized);

			if(write(umbilical, pretty, strlen(pretty)) == -1 || write(umbilical, "\n", 1) == -1) {
				// Other end broken, nothing we can do about it.
			}
		}
	}

	if(logcontrol) {
		suppress = true;
		logcontrol = false;

		size_t msglen = strlen(pretty);

		for list_each(connection_t, c, &connection_list) {
			if(!c->status.log) {
				continue;
			}

			logcontrol = true;

			if(level > (c->log_level != DEBUG_UNSET ? c->log_level : debug_level)) {
				continue;
			}

			if(format_pretty(pretty, sizeof(pretty), priority, message, c->status.log_color, &pretty_colorized)) {
				msglen = strlen(pretty);
			}

			if(send_request(c, "%d %d %lu", CONTROL, REQ_LOG, (unsigned long)msglen)) {
				send_meta(c, pretty, msglen);
			}
		}

		suppress = false;
	}
}

void logger(debug_t level, int priority, const char *format, ...) {
	va_list ap;
	char message[1024] = "";

	if(!should_log(level)) {
		return;
	}

	va_start(ap, format);
	int len = vsnprintf(message, sizeof(message), format, ap);
	message[sizeof(message) - 1] = 0;
	va_end(ap);

	if(len > 0 && (size_t)len < sizeof(message) - 1 && message[len - 1] == '\n') {
		message[len - 1] = 0;
	}

	real_logger(level, priority, message);
}

static void sptps_logger(sptps_t *s, int s_errno, const char *format, va_list ap) ATTR_FORMAT(printf, 3, 0);
static void sptps_logger(sptps_t *s, int s_errno, const char *format, va_list ap) {
	(void)s_errno;
	char message[1024];
	size_t msglen = sizeof(message);

	if(!should_log(DEBUG_TRAFFIC)) {
		return;
	}

	int len = vsnprintf(message, msglen, format, ap);
	message[sizeof(message) - 1] = 0;

	if(len > 0 && (size_t)len < sizeof(message) - 1) {
		if(message[len - 1] == '\n') {
			message[--len] = 0;
		}

		// WARNING: s->handle can point to a connection_t or a node_t,
		// but both types have the name and hostname fields at the same offsets.
		connection_t *c = s->handle;

		if(c) {
			snprintf(message + len, sizeof(message) - len, " from %s (%s)", c->name, c->hostname);
		}
	}

	real_logger(DEBUG_TRAFFIC, LOG_ERR, message);
}

void openlogger(const char *ident, logmode_t mode) {
	logident = ident;
	logmode = mode;

	switch(mode) {
	case LOGMODE_STDERR:
		logpid = getpid();
		colorize_stderr = use_ansi_escapes(stderr);
		break;

	case LOGMODE_FILE:
		logpid = getpid();
		logfile = fopen(logfilename, "a");

		if(!logfile) {
			fprintf(stderr, "Could not open log file %s: %s\n", logfilename, strerror(errno));
			logmode = LOGMODE_NULL;
		}

		break;

	case LOGMODE_SYSLOG:
#ifdef HAVE_WINDOWS
		loghandle = RegisterEventSource(NULL, logident);

		if(!loghandle) {
			fprintf(stderr, "Could not open log handle!\n");
			logmode = LOGMODE_NULL;
		}

		break;
#else
#ifdef HAVE_SYSLOG_H
		openlog(logident, LOG_CONS | LOG_PID, LOG_DAEMON);
		break;
#endif
#endif

	case LOGMODE_NULL:
	default:
		break;
	}

	if(logmode != LOGMODE_NULL) {
		sptps_log = sptps_logger;
	} else {
		sptps_log = sptps_log_quiet;
	}
}

void reopenlogger(void) {
	if(logmode != LOGMODE_FILE) {
		return;
	}

	fflush(logfile);
	FILE *newfile = fopen(logfilename, "a");

	if(!newfile) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Unable to reopen log file %s: %s", logfilename, strerror(errno));
		return;
	}

	fclose(logfile);
	logfile = newfile;
}


void closelogger(void) {
	switch(logmode) {
	case LOGMODE_FILE:
		fclose(logfile);
		break;

	case LOGMODE_SYSLOG:
#ifdef HAVE_WINDOWS
		DeregisterEventSource(loghandle);
		break;
#else
#ifdef HAVE_SYSLOG_H
		closelog();
		break;
#endif
#endif

	case LOGMODE_NULL:
	case LOGMODE_STDERR:
	default:
		break;
	}
}
