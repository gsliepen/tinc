/*
    netutl.h -- header file for netutl.c
    Copyright (C) 1998-2002 Ivo Timmermans <zarq@iname.com>
                  2000-2002 Guus Sliepen <guus@sliepen.warande.net>

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

    $Id: netutl.h,v 1.2.4.11 2002/03/17 15:59:29 guus Exp $
*/

#ifndef __TINC_NETUTL_H__
#define __TINC_NETUTL_H__

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include "net.h"

extern int hostnames;

extern char *hostlookup(unsigned long);
extern struct addrinfo *str2addrinfo(char *, char *, int);
extern sockaddr_t str2sockaddr(char *, char *);
extern void sockaddr2str(sockaddr_t *, char **, char **);
extern char *sockaddr2hostname(sockaddr_t *);
extern int sockaddrcmp(sockaddr_t *, sockaddr_t *);
extern void sockaddrunmap(sockaddr_t *);
extern int maskcmp(char *, char *, int, int);
extern void maskcpy(char *, char *, int, int);
extern void mask(char *, int, int);
extern int maskcheck(char *, int, int);

#endif /* __TINC_NETUTL_H__ */
