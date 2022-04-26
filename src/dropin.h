#ifndef TINC_DROPIN_H
#define TINC_DROPIN_H

/*
    dropin.h -- header file for dropin.c
    Copyright (C) 2000-2005 Ivo Timmermans,
                  2000-2022 Guus Sliepen <guus@tinc-vpn.org>

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

#ifndef HAVE_DAEMON
extern int daemon(int, int);
#endif

#ifndef HAVE_ASPRINTF
extern int asprintf(char **, const char *, ...) ATTR_FORMAT(printf, 2, 3);
extern int vasprintf(char **, const char *, va_list ap) ATTR_FORMAT(printf, 2, 0);
#endif

#ifndef HAVE_GETTIMEOFDAY
extern int gettimeofday(struct timeval *, void *);
#endif

#ifndef timeradd
#define timeradd(a, b, r) do {\
		(r)->tv_sec = (a)->tv_sec + (b)->tv_sec;\
		(r)->tv_usec = (a)->tv_usec + (b)->tv_usec;\
		if((r)->tv_usec >= 1000000)\
			(r)->tv_sec++, (r)->tv_usec -= 1000000;\
	} while (0)
#endif

#ifndef timersub
#define timersub(a, b, r) do {\
		(r)->tv_sec = (a)->tv_sec - (b)->tv_sec;\
		(r)->tv_usec = (a)->tv_usec - (b)->tv_usec;\
		if((r)->tv_usec < 0)\
			(r)->tv_sec--, (r)->tv_usec += 1000000;\
	} while (0)
#endif

#ifdef HAVE_WINDOWS
#define mkdir(a, b) mkdir(a)
#ifndef SHUT_RDWR
#define SHUT_RDWR SD_BOTH
#endif
#endif

#ifndef EAI_SYSTEM
#define EAI_SYSTEM 0
#endif

#ifndef MIN
#define MIN(a,b) (((a)<(b))?(a):(b))
#endif

#ifndef MAX
#define MAX(a,b) (((a)>(b))?(a):(b))
#endif

#define CLAMP(val, min, max) MIN((max), MAX((min), (val)))

#ifdef _MSC_VER

#define PATH_MAX MAX_PATH
#define strcasecmp _stricmp
#define strncasecmp _strnicmp
#define isatty _isatty
#define fileno _fileno
#define close CloseHandle
#define __const const

typedef int mode_t;
typedef int pid_t;
typedef SSIZE_T ssize_t;

static const int STDIN_FILENO = 0;
static const int F_OK = 0;
static const int X_OK = 0;
static const int W_OK = 2;
static const int R_OK = 4;

#else // _MSC_VER

#endif // _MSC_VER

extern bool sleep_millis(unsigned int ms);

#endif // TINC_DROPIN_H
