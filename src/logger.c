/*
    logger.c -- logging code
    Copyright (C) 2003 Guus Sliepen <guus@sliepen.eu.org>
                  2003 Ivo Timmermans <ivo@o2w.nl>

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.

    $Id: logger.c,v 1.1.2.3 2003/07/12 17:41:45 guus Exp $
*/

#include <stdio.h>
#include <stdarg.h>
#include <syslog.h>
#include <unistd.h>

#include "conf.h"
#include "logger.h"

#include "system.h"

int debug_level = DEBUG_NOTHING;
static int logmode = LOGMODE_STDERR;
static pid_t logpid;
extern char *logfilename;
static FILE *logfile = NULL;
static const char *logident = NULL;

void openlogger(const char *ident, int mode) {
	logident = ident;
	logmode = mode;
	
	switch(mode) {
		case LOGMODE_STDERR:
			logpid = getpid();
			break;
		case LOGMODE_FILE:
			logpid = getpid();
			logfile = fopen(logfilename, "a");
			if(!logfile)
				logmode = LOGMODE_NULL;
			break;
		case LOGMODE_SYSLOG:
			openlog(logident, LOG_CONS | LOG_PID, LOG_DAEMON);
			break;
	}
}

void logger(int priority, const char *format, ...) {
	va_list ap;

	va_start(ap, format);

	switch(logmode) {
		case LOGMODE_STDERR:
			vfprintf(stderr, format, ap);
			fprintf(stderr, "\n");
			break;
		case LOGMODE_FILE:
			fprintf(logfile, "%ld %s[%d]: ", time(NULL), logident, logpid);
			vfprintf(logfile, format, ap);
			fprintf(logfile, "\n");
			break;
		case LOGMODE_SYSLOG:
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
	}

	va_end(ap);
}

void closelogger(void) {
	switch(logmode) {
		case LOGMODE_FILE:
			fclose(logfile);
			break;
		case LOGMODE_SYSLOG:
			closelog();
			break;
	}
}
