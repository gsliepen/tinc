/*
    netutl.h -- header file for netutl.c
    Copyright (C) 1998,1999,2000 Ivo Timmermans <zarq@iname.com>

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

    $Id: netutl.h,v 1.2.4.4 2000/11/04 11:49:58 guus Exp $
*/

#ifndef __TINC_NETUTL_H__
#define __TINC_NETUTL_H__

#include "net.h"
#include "conf.h"

extern void destroy_queue(packet_queue_t *);
extern char *hostlookup(unsigned long);
extern ip_mask_t *strtoip(char*);

#endif /* __TINC_NETUTL_H__ */
