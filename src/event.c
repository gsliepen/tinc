/*
    event.c -- event queue
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

#include "system.h"

#include "avl_tree.h"
#include "event.h"
#include "utils.h"
#include "xalloc.h"

avl_tree_t *event_tree;
extern time_t now;

static int id;

static int event_compare(const event_t *a, const event_t *b) {
	if(a->time > b->time) {
		return 1;
	}

	if(a->time < b->time) {
		return -1;
	}

	return a->id - b->id;
}

void init_events(void) {
	event_tree = avl_alloc_tree((avl_compare_t) event_compare, (avl_action_t) free_event);
}

void exit_events(void) {
	avl_delete_tree(event_tree);
}

void expire_events(void) {
	avl_node_t *node;
	event_t *event;
	time_t diff;

	/*
	 * Make all events appear expired by subtracting the difference between
	 * the expiration time of the last event and the current time.
	 */

	if(!event_tree->tail) {
		return;
	}

	event = event_tree->tail->data;

	if(event->time <= now) {
		return;
	}

	diff = event->time - now;

	for(node = event_tree->head; node; node = node->next) {
		event = node->data;
		event->time -= diff;
	}
}

event_t *new_event(void) {
	return xmalloc_and_zero(sizeof(event_t));
}

void free_event(event_t *event) {
	free(event);
}

void event_add(event_t *event) {
	event->id = ++id;
	avl_insert(event_tree, event);
}

void event_del(event_t *event) {
	avl_delete(event_tree, event);
}

event_t *get_expired_event(void) {
	event_t *event;

	if(event_tree->head) {
		event = event_tree->head->data;

		if(event->time <= now) {
			avl_node_t *node = event_tree->head;
			avl_unlink_node(event_tree, node);
			free(node);
			return event;
		}
	}

	return NULL;
}

event_t *peek_next_event(void) {
	if(event_tree->head) {
		return event_tree->head->data;
	}

	return NULL;
}
