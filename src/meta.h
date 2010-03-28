/*
    meta.h -- header for meta.c
    Copyright (C) 2000-2006 Guus Sliepen <guus@tinc-vpn.org>,
                  2000-2005 Ivo Timmermans

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

#ifndef __TINC_META_H__
#define __TINC_META_H__

#include "connection.h"

extern bool send_meta(struct connection_t *, const char *, int);
extern void broadcast_meta(struct connection_t *, const char *, int);
extern bool receive_meta(struct connection_t *);

#endif							/* __TINC_META_H__ */
