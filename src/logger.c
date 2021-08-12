/*
    logger.c -- logging code
    Copyright (C) 2004-2017 Guus Sliepen <guus@tinc-vpn.org>
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
#include "compression.h"

debug_t debug_level = DEBUG_NOTHING;
static logmode_t logmode = LOGMODE_STDERR;
static pid_t logpid;
static FILE *logfile = NULL;
#ifdef HAVE_MINGW
static HANDLE loghandle = NULL;
#endif
static const char *logident = NULL;
bool logcontrol = false; // controlled by REQ_LOG <level>
int umbilical = 0;

static bool should_log(debug_t level) {
	return (level <= debug_level && logmode != LOGMODE_NULL) || logcontrol;
}

static void real_logger(debug_t level, int priority, const char *message) {
	char timestr[32] = "";
	static bool suppress = false;

	if(suppress) {
		return;
	}

	if(level <= debug_level) {
		switch(logmode) {
		case LOGMODE_STDERR:
			fprintf(stderr, "%s\n", message);
			fflush(stderr);
			break;

		case LOGMODE_FILE:
			if(!now.tv_sec) {
				gettimeofday(&now, NULL);
			}

			time_t now_sec = now.tv_sec;
			strftime(timestr, sizeof(timestr), "%Y-%m-%d %H:%M:%S", localtime(&now_sec));
			fprintf(logfile, "%s %s[%ld]: %s\n", timestr, logident, (long)logpid, message);
			fflush(logfile);
			break;

		case LOGMODE_SYSLOG:
#ifdef HAVE_MINGW
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
			write(umbilical, message, strlen(message));
			write(umbilical, "\n", 1);
		}
	}

	if(logcontrol) {
		suppress = true;
		logcontrol = false;

		for list_each(connection_t, c, &connection_list) {
			if(!c->status.log) {
				continue;
			}

			logcontrol = true;

			if(level > (c->outcompression >= COMPRESS_NONE ? c->outcompression : debug_level)) {
				continue;
			}

			size_t len = strlen(message);

			if(send_request(c, "%d %d %zu", CONTROL, REQ_LOG, len)) {
				send_meta(c, message, len);
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

static void sptps_logger(sptps_t *s, int s_errno, const char *format, va_list ap) {
	(void)s_errno;
	char message[1024];
	size_t msglen = sizeof(message);

	if(!should_log(DEBUG_ALWAYS)) {
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

	real_logger(DEBUG_ALWAYS, LOG_ERR, message);
}

void openlogger(const char *ident, logmode_t mode) {
	logident = ident;
	logmode = mode;

	switch(mode) {
	case LOGMODE_STDERR:
		logpid = getpid();
		break;

	case LOGMODE_FILE:
		logpid = getpid();
		logfile = fopen(logfilename, "a");

		if(!logfile) {
			fprintf(stderr, _("Could not open log file %s: %s\n"), logfilename, strerror(errno));
			logmode = LOGMODE_NULL;
		}

		break;

	case LOGMODE_SYSLOG:
#ifdef HAVE_MINGW
		loghandle = RegisterEventSource(NULL, logident);

		if(!loghandle) {
			fprintf(stderr, _("Could not open log handle!\n"));
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

void reopenlogger() {
	if(logmode != LOGMODE_FILE) {
		return;
	}

	fflush(logfile);
	FILE *newfile = fopen(logfilename, "a");

	if(!newfile) {
		logger(DEBUG_ALWAYS, LOG_ERR, _("Unable to reopen log file %s: %s"), logfilename, strerror(errno));
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
#ifdef HAVE_MINGW
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
