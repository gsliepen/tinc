#ifndef TINC_DROPIN_H
#define TINC_DROPIN_H

/*
    dropin.h -- header file for dropin.c
    Copyright (C) 2000-2005 Ivo Timmermans,
                  2000-2011 Guus Sliepen <guus@tinc-vpn.org>

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

#include "fake-getaddrinfo.h"
#include "fake-getnameinfo.h"

#ifndef HAVE_DAEMON
extern int daemon(int nochdir, int noclose);
#endif

#ifndef HAVE_GET_CURRENT_DIR_NAME
extern char *get_current_dir_name(void);
#endif

#ifndef HAVE_ASPRINTF
extern int asprintf(char **buf, const char *fmt, ...);
extern int vasprintf(char **buf, const char *fmt, va_list ap);
#endif

#ifndef HAVE_GETTIMEOFDAY
extern int gettimeofday(struct timeval *tv, void *tz);
#endif

#ifndef HAVE_USLEEP
extern int usleep(long long usec);
#endif

#endif
