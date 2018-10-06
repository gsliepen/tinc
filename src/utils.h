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

extern size_t hex2bin(const char *src, void *dst, size_t length);
extern size_t bin2hex(const void *src, char *dst, size_t length);

extern size_t b64encode(const void *src, char *dst, size_t length);
extern size_t b64encode_urlsafe(const void *src, char *dst, size_t length);
extern size_t b64decode(const char *src, void *dst, size_t length);

#ifdef HAVE_MINGW
extern const char *winerror(int);
#define strerror(x) ((x)>0?strerror(x):winerror(GetLastError()))
#define sockerrno WSAGetLastError()
#define sockstrerror(x) winerror(x)
#define sockwouldblock(x) ((x) == WSAEWOULDBLOCK || (x) == WSAEINTR)
#define sockmsgsize(x) ((x) == WSAEMSGSIZE)
#define sockinprogress(x) ((x) == WSAEINPROGRESS || (x) == WSAEWOULDBLOCK)
#define sockinuse(x) ((x) == WSAEADDRINUSE)
#define socknotconn(x) ((x) == WSAENOTCONN)
#else
#define sockerrno errno
#define sockstrerror(x) strerror(x)
#define sockwouldblock(x) ((x) == EWOULDBLOCK || (x) == EINTR)
#define sockmsgsize(x) ((x) == EMSGSIZE)
#define sockinprogress(x) ((x) == EINPROGRESS)
#define sockinuse(x) ((x) == EADDRINUSE)
#define socknotconn(x) ((x) == ENOTCONN)
#endif

extern unsigned int bitfield_to_int(const void *bitfield, size_t size);

extern bool check_id(const char *id);
extern bool check_netname(const char *netname, bool strict);
char *replace_name(const char *name);

#endif
