/*
    event.c -- event queue
    Copyright (C) 2002-2003 Guus Sliepen <guus@sliepen.eu.org>,
                  2002-2003 Ivo Timmermans <ivo@o2w.nl>

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

    $Id: event.c,v 1.1.4.10 2003/07/24 12:08:15 guus Exp $
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

event_t *new_event(void)
{
	cp();

	return (event_t *) xmalloc_and_zero(sizeof(event_t));
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
		event = (event_t *) event_tree->head->data;

		if(event->time < now) {
			avl_delete(event_tree, event);
			return event;
		}
	}

	return NULL;
}
