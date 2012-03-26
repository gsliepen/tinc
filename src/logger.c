/*
    logger.c -- logging code
    Copyright (C) 2004-2006 Guus Sliepen <guus@tinc-vpn.org>
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
#include "logger.h"

debug_t debug_level = DEBUG_NOTHING;
static logmode_t logmode = LOGMODE_STDERR;
static pid_t logpid;
extern char *logfilename;
static FILE *logfile = NULL;
#ifdef HAVE_MINGW
static HANDLE loghandle = NULL;
#endif
static const char *logident = NULL;

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
				fprintf(stderr, "Could not open log file %s: %s\n", logfilename, strerror(errno));
				logmode = LOGMODE_NULL;
			}
			break;
		case LOGMODE_SYSLOG:
#ifdef HAVE_MINGW
			loghandle = RegisterEventSource(NULL, logident);
			if(!loghandle) {
				fprintf(stderr, "Could not open log handle!");
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
			break;
	}
}

void reopenlogger() {
	if(logmode != LOGMODE_FILE)
		return;

	fflush(logfile);
	FILE *newfile = fopen(logfilename, "a");
	if(!newfile) {
		logger(LOG_ERR, "Unable to reopen log file %s: %s", logfilename, strerror(errno));
		return;
	}
	fclose(logfile);
	logfile = newfile;
}

void logger(int priority, const char *format, ...) {
	va_list ap;
	char timestr[32] = "";
	time_t now;

	va_start(ap, format);

	switch(logmode) {
		case LOGMODE_STDERR:
			vfprintf(stderr, format, ap);
			fprintf(stderr, "\n");
			fflush(stderr);
			break;
		case LOGMODE_FILE:
			now = time(NULL);
			strftime(timestr, sizeof timestr, "%Y-%m-%d %H:%M:%S", localtime(&now));
			fprintf(logfile, "%s %s[%ld]: ", timestr, logident, (long)logpid);
			vfprintf(logfile, format, ap);
			fprintf(logfile, "\n");
			fflush(logfile);
			break;
		case LOGMODE_SYSLOG:
#ifdef HAVE_MINGW
			{
				char message[4096];
				const char *messages[] = {message};
				vsnprintf(message, sizeof(message), format, ap);
				ReportEvent(loghandle, priority, 0, 0, NULL, 1, 0, messages, NULL);
			}
#else
#ifdef HAVE_SYSLOG_H
#ifdef HAVE_VSYSLOG
			vsyslog(priority, format, ap);
#else
			{
				char message[4096];
				vsnprintf(message, sizeof(message), format, ap);
				syslog(priority, "%s", message);
			}
#endif
			break;
#endif
#endif
		case LOGMODE_NULL:
			break;
	}

	va_end(ap);
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
			break;
			break;
	}
}
