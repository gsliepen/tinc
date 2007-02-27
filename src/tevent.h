/*
    event.h -- header for event.c
    Copyright (C) 2002-2006 Guus Sliepen <guus@tinc-vpn.org>,
                  2002-2005 Ivo Timmermans

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

    $Id$
*/

#ifndef __TINC_EVENT_H__
#define __TINC_EVENT_H__

#include "avl_tree.h"

extern avl_tree_t *tevent_tree;

typedef void (*event_handler_t)(void *);

typedef struct {
	time_t time;
	int id;
	event_handler_t handler;
	void *data;
} tevent_t;

extern void init_tevents(void);
extern void exit_tevents(void);
extern void flush_tevents(void);
extern tevent_t *new_tevent(void) __attribute__ ((__malloc__));
extern void free_tevent(tevent_t *);
extern void tevent_add(tevent_t *);
extern void tevent_del(tevent_t *);
extern tevent_t *get_expired_tevent(void);

#endif							/* __TINC_EVENT_H__ */
