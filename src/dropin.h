/*
    dropin.h -- header file for dropin.c
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

#ifndef __DROPIN_H__
#define __DROPIN_H__

#ifndef HAVE_DAEMON
extern int daemon(int, int);
#endif

#ifndef HAVE_ASPRINTF
extern int asprintf(char **, const char *, ...);
extern int vasprintf(char **, const char *, va_list ap);
#endif

#ifndef HAVE_GETTIMEOFDAY
extern int gettimeofday(struct timeval *, void *);
#endif

#ifndef HAVE_NANOSLEEP
extern int nanosleep(const struct timespec *req, struct timespec *rem);
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

#ifdef HAVE_MINGW
#define mkdir(a, b) mkdir(a)
#ifndef SHUT_RDWR
#define SHUT_RDWR SD_BOTH
#endif
#endif

#ifndef EAI_SYSTEM
#define EAI_SYSTEM 0
#endif

#endif /* __DROPIN_H__ */
