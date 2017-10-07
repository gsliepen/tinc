/*
    list.c -- functions to deal with double linked lists
    Copyright (C) 2000-2005 Ivo Timmermans
                  2000-2013 Guus Sliepen <guus@tinc-vpn.org>

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

#include "list.h"
#include "xalloc.h"

/* (De)constructors */

list_t *list_alloc(list_action_t delete) {
	list_t *list = xzalloc(sizeof(list_t));
	list->delete = delete;

	return list;
}

void list_free(list_t *list) {
	free(list);
}

list_node_t *list_alloc_node(void) {
	return xzalloc(sizeof(list_node_t));
}

void list_free_node(list_t *list, list_node_t *node) {
	if(node->data && list->delete) {
		list->delete(node->data);
	}

	free(node);
}

/* Insertion and deletion */

list_node_t *list_insert_head(list_t *list, void *data) {
	list_node_t *node = list_alloc_node();

	node->data = data;
	node->prev = NULL;
	node->next = list->head;
	list->head = node;

	if(node->next) {
		node->next->prev = node;
	} else {
		list->tail = node;
	}

	list->count++;

	return node;
}

list_node_t *list_insert_tail(list_t *list, void *data) {
	list_node_t *node = list_alloc_node();

	node->data = data;
	node->next = NULL;
	node->prev = list->tail;
	list->tail = node;

	if(node->prev) {
		node->prev->next = node;
	} else {
		list->head = node;
	}

	list->count++;

	return node;
}

list_node_t *list_insert_after(list_t *list, list_node_t *after, void *data) {
	list_node_t *node = list_alloc_node();

	node->data = data;
	node->next = after->next;
	node->prev = after;
	after->next = node;

	if(node->next) {
		node->next->prev = node;
	} else {
		list->tail = node;
	}

	list->count++;

	return node;
}

list_node_t *list_insert_before(list_t *list, list_node_t *before, void *data) {
	list_node_t *node;

	node = list_alloc_node();

	node->data = data;
	node->next = before;
	node->prev = before->prev;
	before->prev = node;

	if(node->prev) {
		node->prev->next = node;
	} else {
		list->head = node;
	}

	list->count++;

	return node;
}

void list_unlink_node(list_t *list, list_node_t *node) {
	if(node->prev) {
		node->prev->next = node->next;
	} else {
		list->head = node->next;
	}

	if(node->next) {
		node->next->prev = node->prev;
	} else {
		list->tail = node->prev;
	}

	list->count--;
}

void list_delete_node(list_t *list, list_node_t *node) {
	list_unlink_node(list, node);
	list_free_node(list, node);
}

void list_delete_head(list_t *list) {
	list_delete_node(list, list->head);
}

void list_delete_tail(list_t *list) {
	list_delete_node(list, list->tail);
}

void list_delete(list_t *list, const void *data) {
	for(list_node_t *node = list->head, *next; next = node ? node->next : NULL, node; node = next)
		if(node->data == data) {
			list_delete_node(list, node);
		}
}

/* Head/tail lookup */

void *list_get_head(list_t *list) {
	if(list->head) {
		return list->head->data;
	} else {
		return NULL;
	}
}

void *list_get_tail(list_t *list) {
	if(list->tail) {
		return list->tail->data;
	} else {
		return NULL;
	}
}

/* Fast list deletion */

void list_delete_list(list_t *list) {
	for(list_node_t *node = list->head, *next; next = node ? node->next : NULL, node; node = next) {
		list_free_node(list, node);
	}

	list_free(list);
}

/* Traversing */

void list_foreach_node(list_t *list, list_action_node_t action) {
	for(list_node_t *node = list->head, *next; next = node ? node->next : NULL, node; node = next) {
		action(node);
	}
}

void list_foreach(list_t *list, list_action_t action) {
	for(list_node_t *node = list->head, *next; next = node ? node->next : NULL, node; node = next)
		if(node->data) {
			action(node->data);
		}
}
