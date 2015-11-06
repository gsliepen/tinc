/*
    proxy.h -- header for proxy.c
    Copyright (C) 2015 Guus Sliepen <guus@tinc-vpn.org>

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

#ifndef __TINC_PROXY_H__
#define __TINC_PROXY_H__

#include "connection.h"

typedef enum proxytype_t {
	PROXY_NONE = 0,
	PROXY_SOCKS4,
	PROXY_SOCKS4A,
	PROXY_SOCKS5,
	PROXY_HTTP,
	PROXY_EXEC,
} proxytype_t;

extern proxytype_t proxytype;
extern char *proxyhost;
extern char *proxyport;
extern char *proxyuser;
extern char *proxypass;

extern bool send_proxyrequest(struct connection_t *c);
extern int receive_proxy_meta(struct connection_t *c, int start, int lenin);

#endif
