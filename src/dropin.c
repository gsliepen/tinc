/*
    dropin.c -- a set of drop-in replacements for libc functions
    Copyright (C) 2000-2005 Ivo Timmermans,
                  2000-2016 Guus Sliepen <guus@tinc-vpn.org>

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

#include "xalloc.h"

#ifndef HAVE_DAEMON
/*
  Replacement for the daemon() function.

  The daemon() function is for programs wishing to detach themselves
  from the controlling terminal and run in the background as system
  daemons.

  Unless the argument nochdir is non-zero, daemon() changes the
  current working directory to the root (``/'').

  Unless the argument noclose is non-zero, daemon() will redirect
  standard input, standard output and standard error to /dev/null.
*/
int daemon(int nochdir, int noclose) {
#ifdef HAVE_FORK
	pid_t pid;
	int fd;

	pid = fork();

	/* Check if forking failed */
	if(pid < 0) {
		perror("fork");
		exit(-1);
	}

	/* If we are the parent, terminate */
	if(pid)
		exit(0);

	/* Detach by becoming the new process group leader */
	if(setsid() < 0) {
		perror("setsid");
		return -1;
	}

	/* Change working directory to the root (to avoid keeping mount
	   points busy) */
	if(!nochdir) {
		chdir("/");
	}

	/* Redirect stdin/out/err to /dev/null */
	if(!noclose) {
		fd = open("/dev/null", O_RDWR);

		if(fd < 0) {
			perror("opening /dev/null");
			return -1;
		} else {
			dup2(fd, 0);
			dup2(fd, 1);
			dup2(fd, 2);
		}
	}

	return 0;
#else
	return -1;
#endif
}
#endif

#ifndef HAVE_ASPRINTF
int asprintf(char **buf, const char *fmt, ...) {
	int result;
	va_list ap;
	va_start(ap, fmt);
	result = vasprintf(buf, fmt, ap);
	va_end(ap);
	return result;
}

int vasprintf(char **buf, const char *fmt, va_list ap) {
	int status;
	va_list aq;
	int len;

	len = 4096;
	*buf = xmalloc(len);

	va_copy(aq, ap);
	status = vsnprintf(*buf, len, fmt, aq);
	buf[len - 1] = 0;
	va_end(aq);

	if(status >= 0)
		*buf = xrealloc(*buf, status + 1);

	if(status > len - 1) {
		len = status;
		va_copy(aq, ap);
		status = vsnprintf(*buf, len, fmt, aq);
		va_end(aq);
	}

	return status;
}
#endif

#ifndef HAVE_GETTIMEOFDAY
int gettimeofday(struct timeval *tv, void *tz) {
#ifdef HAVE_MINGW
	FILETIME ft;
	GetSystemTimeAsFileTime(&ft);
	uint64_t lt = (uint64_t)ft.dwLowDateTime | ((uint64_t)ft.dwHighDateTime << 32);
	lt -= 116444736000000000ULL;
	tv->tv_sec = lt / 10000000;
	tv->tv_usec = (lt / 10) % 1000000;
#else
#warning No high resolution time source!
	tv->tv_sec = time(NULL);
	tv->tv_usec = 0;
#endif
	return 0;
}
#endif

#ifndef HAVE_NANOSLEEP
int nanosleep(const struct timespec *req, struct timespec *rem) {
	struct timeval tv = {req->tv_sec, req->tv_nsec / 1000};
	return select(0, NULL, NULL, NULL, &tv);
}
#endif
