/*
    event.h -- header for event.c
    Copyright (C) 2002-2009 Guus Sliepen <guus@tinc-vpn.org>,
                  2002-2005 Ivo Timmermans

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

#ifndef __TINC_EVENT_H__
#define __TINC_EVENT_H__

#include "avl_tree.h"

extern avl_tree_t *event_tree;

typedef void (*event_handler_t)(void *);

typedef struct {
	time_t time;
	int id;
	event_handler_t handler;
	void *data;
} event_t;

extern void init_events(void);
extern void exit_events(void);
extern void expire_events(void);
extern event_t *new_event(void) __attribute__ ((__malloc__));
extern void free_event(event_t *);
extern void event_add(event_t *);
extern void event_del(event_t *);
extern event_t *get_expired_event(void);

#endif							/* __TINC_EVENT_H__ */
