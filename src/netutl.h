/*
    netutl.h -- header file for netutl.c
    Copyright (C) 1998,99 Ivo Timmermans <zarq@iname.com>

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
*/

#ifndef __TINC_NETUTL_H__
#define __TINC_NETUTL_H__

#include "net.h"

extern conn_list_t *lookup_conn(ip_t);
extern void free_conn_element(conn_list_t *);
extern void free_conn_list(conn_list_t*);
extern void prune_conn_list(void);
extern conn_list_t *new_conn_list(void);
extern void destroy_conn_list(void);
extern char *hostlookup(unsigned long);
extern ip_mask_t *strtoip(char*);
extern void dump_conn_list(void);

#endif /* __TINC_NETUTL_H__ */
