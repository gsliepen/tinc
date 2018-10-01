#ifndef TINC_META_H
#define TINC_META_H

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

#include "connection.h"

extern bool send_meta(struct connection_t *c, const char *buffer, int length);
extern void broadcast_meta(struct connection_t *c, const char *buffer, int length);
extern bool flush_meta(struct connection_t *c);
extern bool receive_meta(struct connection_t *c);

#endif
