/*
    event.h -- header for event.c
    Copyright (C) 2002 Guus Sliepen <guus@sliepen.warande.net>,
                  2002 Ivo Timmermans <itimmermans@bigfoot.com>

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

    $Id: event.h,v 1.1.4.1 2002/02/11 10:05:58 guus Exp $
*/

#ifndef __TINC_EVENT_H__
#define __TINC_EVENT_H__

#include <time.h>
#include <avl_tree.h>

avl_tree_t *event_tree;

typedef void (*event_handler_t)(void *);

typedef struct {
  time_t time;
  int id;
  event_handler_t handler;
  void *data;
} event_t;

extern void init_events(void);
extern void exit_events(void);
extern event_t *new_event(void);
extern void free_event(event_t *);
extern void event_add(event_t *);
extern void event_del(event_t *);
extern event_t *get_expired_event(void);

#endif /* __TINC_EVENT_H__ */
