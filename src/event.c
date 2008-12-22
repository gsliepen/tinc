/*
    event.c -- event queue
    Copyright (C) 2002-2007 Guus Sliepen <guus@tinc-vpn.org>,
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

#include "system.h"

#include "avl_tree.h"
#include "event.h"
#include "utils.h"
#include "xalloc.h"

avl_tree_t *event_tree;
extern time_t now;

int id;

static int event_compare(const event_t *a, const event_t *b)
{
	if(a->time > b->time)
		return 1;

	if(a->time < b->time)
		return -1;

	return a->id - b->id;
}

void init_events(void)
{
	cp();

	event_tree = avl_alloc_tree((avl_compare_t) event_compare, NULL);
}

void exit_events(void)
{
	cp();

	avl_delete_tree(event_tree);
}

void flush_events(void)
{
	avl_tree_t *to_flush;
	event_t *event;

	/*
	 * Events can be inserted from event handlers, so only flush events
	 * already in the priority queue.
	 */

	cp();

	to_flush = event_tree;
	init_events();
	while (to_flush->head) {
		event = to_flush->head->data;
		event->handler(event->data);
		avl_delete(to_flush, event);
	}
	avl_delete_tree(to_flush);
}

event_t *new_event(void)
{
	cp();

	return xmalloc_and_zero(sizeof(event_t));
}

void free_event(event_t *event)
{
	cp();

	free(event);
}

void event_add(event_t *event)
{
	cp();

	event->id = ++id;
	avl_insert(event_tree, event);
}

void event_del(event_t *event)
{
	cp();

	avl_delete(event_tree, event);
}

event_t *get_expired_event(void)
{
	event_t *event;

	cp();

	if(event_tree->head) {
		event = event_tree->head->data;

		if(event->time < now) {
			event_del(event);
			return event;
		}
	}

	return NULL;
}
