/*
    netutl.h -- header file for netutl.c
    Copyright (C) 1998-2003 Ivo Timmermans <zarq@iname.com>
                  2000-2003 Guus Sliepen <guus@sliepen.eu.org>

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

    $Id: netutl.h,v 1.2.4.18 2003/07/24 12:08:15 guus Exp $
*/

#ifndef __TINC_NETUTL_H__
#define __TINC_NETUTL_H__

#include "net.h"

extern bool hostnames;

extern struct addrinfo *str2addrinfo(const char *, const char *, int);
extern sockaddr_t str2sockaddr(const char *, const char *);
extern void sockaddr2str(const sockaddr_t *, char **, char **);
extern char *sockaddr2hostname(const sockaddr_t *);
extern int sockaddrcmp(const sockaddr_t *, const sockaddr_t *);
extern void sockaddrunmap(sockaddr_t *);
extern int maskcmp(const void *, const void *, int, int);
extern void maskcpy(void *, const void *, int, int);
extern void mask(void *, int, int);
extern bool maskcheck(const void *, int, int);

#endif							/* __TINC_NETUTL_H__ */
