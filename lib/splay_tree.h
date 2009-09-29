/*
    splay_tree.h -- header file for splay_tree.c
    Copyright (C) 2004-2006 Guus Sliepen <guus@tinc-vpn.org>

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


#ifndef __SPLAY_TREE_H__
#define __SPLAY_TREE_H__

typedef struct splay_node_t {

	/* Linked list part */

	struct splay_node_t *next;
	struct splay_node_t *prev;

	/* Tree part */

	struct splay_node_t *parent;
	struct splay_node_t *left;
	struct splay_node_t *right;

	/* Payload */

	void *data;

} splay_node_t;

typedef int (*splay_compare_t)(const void *, const void *);
typedef void (*splay_action_t)(const void *);
typedef void (*splay_action_node_t)(const splay_node_t *);

typedef struct splay_tree_t {

	/* Linked list part */

	splay_node_t *head;
	splay_node_t *tail;

	/* Tree part */

	splay_node_t *root;

	splay_compare_t compare;
	splay_action_t delete;

} splay_tree_t;

/* (De)constructors */

extern splay_tree_t *splay_alloc_tree(splay_compare_t, splay_action_t);
extern void splay_free_tree(splay_tree_t *);

extern splay_node_t *splay_alloc_node(void);
extern void splay_free_node(splay_tree_t *tree, splay_node_t *);

/* Insertion and deletion */

extern splay_node_t *splay_insert(splay_tree_t *, void *);
extern splay_node_t *splay_insert_node(splay_tree_t *, splay_node_t *);

extern void splay_insert_top(splay_tree_t *, splay_node_t *);
extern void splay_insert_before(splay_tree_t *, splay_node_t *, splay_node_t *);
extern void splay_insert_after(splay_tree_t *, splay_node_t *, splay_node_t *);

extern splay_node_t *splay_unlink(splay_tree_t *, void *);
extern void splay_unlink_node(splay_tree_t *tree, splay_node_t *);
extern void splay_delete(splay_tree_t *, void *);
extern void splay_delete_node(splay_tree_t *, splay_node_t *);

/* Fast tree cleanup */

extern void splay_delete_tree(splay_tree_t *);

/* Searching */

extern void *splay_search(splay_tree_t *, const void *);
extern void *splay_search_closest(splay_tree_t *, const void *, int *);
extern void *splay_search_closest_smaller(splay_tree_t *, const void *);
extern void *splay_search_closest_greater(splay_tree_t *, const void *);

extern splay_node_t *splay_search_node(splay_tree_t *, const void *);
extern splay_node_t *splay_search_closest_node(splay_tree_t *, const void *, int *);
extern splay_node_t *splay_search_closest_node_nosplay(const splay_tree_t *, const void *, int *);
extern splay_node_t *splay_search_closest_smaller_node(splay_tree_t *, const void *);
extern splay_node_t *splay_search_closest_greater_node(splay_tree_t *, const void *);

/* Tree walking */

extern void splay_foreach(const splay_tree_t *, splay_action_t);
extern void splay_foreach_node(const splay_tree_t *, splay_action_t);

#endif
