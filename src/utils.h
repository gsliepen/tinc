#ifndef TINC_UTILS_H
#define TINC_UTILS_H

/*
    utils.h -- header file for utils.c
    Copyright (C) 1999-2005 Ivo Timmermans
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

#include "system.h"

#include "crypto.h"

#define B64_SIZE(len) ((len) * 4 / 3 + 5)
#define HEX_SIZE(len) ((len) * 2 + 1)

extern size_t hex2bin(const char *src, void *dst, size_t length);
extern size_t bin2hex(const void *src, char *dst, size_t length);

// Returns true if string represents a base-10 integer.
extern bool is_decimal(const char *str);

// The reverse of atoi().
extern char *int_to_str(int num);

extern size_t b64encode_tinc(const void *src, char *dst, size_t length);
extern size_t b64encode_tinc_urlsafe(const void *src, char *dst, size_t length);
extern size_t b64decode_tinc(const char *src, void *dst, size_t length);

#ifdef HAVE_WINDOWS
extern const char *winerror(int);
#define strerror(x) ((x)>0?strerror(x):winerror(GetLastError()))
#define sockerrno WSAGetLastError()
#define sockstrerror(x) winerror(x)
#define sockwouldblock(x) ((x) == WSAEWOULDBLOCK || (x) == WSAEINTR)
#define sockmsgsize(x) ((x) == WSAEMSGSIZE)
#define sockinprogress(x) ((x) == WSAEINPROGRESS || (x) == WSAEWOULDBLOCK)
#define sockinuse(x) ((x) == WSAEADDRINUSE)
#define socknotconn(x) ((x) == WSAENOTCONN)
#define sockshutdown(x) ((x) == WSAESHUTDOWN)

static inline long jitter(void) {
	return (long)prng(131072);
}
#else
#define sockerrno errno
#define sockstrerror(x) strerror(x)
#define sockwouldblock(x) ((x) == EWOULDBLOCK || (x) == EINTR)
#define sockmsgsize(x) ((x) == EMSGSIZE)
#define sockinprogress(x) ((x) == EINPROGRESS)
#define sockinuse(x) ((x) == EADDRINUSE)
#define socknotconn(x) ((x) == ENOTCONN)

static inline suseconds_t jitter(void) {
	return (suseconds_t)prng(131072);
}
#endif

extern bool check_id(const char *id);
extern bool check_netname(const char *netname, bool strict);
char *replace_name(const char *name) ATTR_MALLOC;

// NULL-safe wrapper around strcmp().
extern bool string_eq(const char *first, const char *second);

#endif
