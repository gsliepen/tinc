/*
    meta.h -- header for meta.c
    Copyright (C) 2000-2002 Guus Sliepen <guus@sliepen.warande.net>,
                  2000-2002 Ivo Timmermans <itimmermans@bigfoot.com>

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

    $Id: meta.h,v 1.1.2.6 2002/02/10 21:57:54 guus Exp $
*/

#ifndef __TINC_META_H__
#define __TINC_META_H__

#include "connection.h"

extern int send_meta(connection_t *, const char *, int);
extern int broadcast_meta(connection_t *, const char *, int);
extern int receive_meta(connection_t *);

#endif /* __TINC_META_H__ */
