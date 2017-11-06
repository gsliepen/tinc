#ifndef TINC_NETUTL_H
#define TINC_NETUTL_H

/*
    netutl.h -- header file for netutl.c
    Copyright (C) 1998-2005 Ivo Timmermans
                  2000-2013 Guus Sliepen <guus@tinc-vpn.org>

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

#include "net.h"

extern bool hostnames;

extern struct addrinfo *str2addrinfo(const char *address, const char *service, int socktype) __attribute__((__malloc__));
extern sockaddr_t str2sockaddr(const char *address, const char *port);
extern void sockaddr2str(const sockaddr_t *sa, char **address, char **port);
extern char *sockaddr2hostname(const sockaddr_t *sa) __attribute__((__malloc__));
extern int sockaddrcmp(const sockaddr_t *a, const sockaddr_t *b);
extern int sockaddrcmp_noport(const sockaddr_t *a, const sockaddr_t *b);
extern void sockaddrunmap(sockaddr_t *sa);
extern void sockaddrfree(sockaddr_t *sa);
extern void sockaddrcpy(sockaddr_t *dest, const sockaddr_t *src);
extern void sockaddr_setport(sockaddr_t *sa, const char *port);

#endif
