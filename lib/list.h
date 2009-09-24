/*
    list.h -- header file for list.c
    Copyright (C) 2000-2005 Ivo Timmermans
                  2000-2006 Guus Sliepen <guus@tinc-vpn.org>

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

#ifndef __TINC_LIST_H__
#define __TINC_LIST_H__

typedef struct list_node_t {
	struct list_node_t *prev;
	struct list_node_t *next;

	/* Payload */

	void *data;
} list_node_t;

typedef void (*list_action_t)(const void *);
typedef void (*list_action_node_t)(const list_node_t *);

typedef struct list_t {
	list_node_t *head;
	list_node_t *tail;
	int count;

	/* Callbacks */

	list_action_t delete;
} list_t;

/* (De)constructors */

extern list_t *list_alloc(list_action_t) __attribute__ ((__malloc__));
extern void list_free(list_t *);
extern list_node_t *list_alloc_node(void);
extern void list_free_node(list_t *, list_node_t *);

/* Insertion and deletion */

extern list_node_t *list_insert_head(list_t *, void *);
extern list_node_t *list_insert_tail(list_t *, void *);

extern void list_unlink_node(list_t *, list_node_t *);
extern void list_delete_node(list_t *, list_node_t *);

extern void list_delete_head(list_t *);
extern void list_delete_tail(list_t *);

/* Head/tail lookup */

extern void *list_get_head(list_t *);
extern void *list_get_tail(list_t *);

/* Fast list deletion */

extern void list_delete_list(list_t *);

/* Traversing */

extern void list_foreach(list_t *, list_action_t);
extern void list_foreach_node(list_t *, list_action_node_t);

#endif							/* __TINC_LIST_H__ */
