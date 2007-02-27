/*
    event.c -- event queue
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

#include "system.h"

#include "avl_tree.h"
#include "tevent.h"
#include "utils.h"
#include "xalloc.h"

avl_tree_t *tevent_tree;
extern time_t now;

int id;

static int tevent_compare(const tevent_t *a, const tevent_t *b)
{
	if(a->time > b->time)
		return 1;

	if(a->time < b->time)
		return -1;

	return a->id - b->id;
}

void init_tevents(void)
{
	cp();

	tevent_tree = avl_alloc_tree((avl_compare_t) tevent_compare, NULL);
}

void exit_tevents(void)
{
	cp();

	avl_delete_tree(tevent_tree);
}

void flush_tevents(void)
{
	avl_tree_t *to_flush;
	tevent_t *event;

	/*
	 * Events can be inserted from event handlers, so only flush events
	 * already in the priority queue.
	 */

	cp();

	to_flush = tevent_tree;
	init_tevents();
	while (to_flush->head) {
		event = to_flush->head->data;
		event->handler(event->data);
		avl_delete(to_flush, event);
	}
	avl_delete_tree(to_flush);
}

tevent_t *new_tevent(void)
{
	cp();

	return xmalloc_and_zero(sizeof(tevent_t));
}

void free_tevent(tevent_t *event)
{
	cp();

	free(event);
}

void tevent_add(tevent_t *event)
{
	cp();

	event->id = ++id;
	avl_insert(tevent_tree, event);
}

void tevent_del(tevent_t *event)
{
	cp();

	avl_delete(tevent_tree, event);
}

tevent_t *get_expired_tevent(void)
{
	tevent_t *event;

	cp();

	if(tevent_tree->head) {
		event = tevent_tree->head->data;

		if(event->time < now) {
			tevent_del(event);
			return event;
		}
	}

	return NULL;
}
