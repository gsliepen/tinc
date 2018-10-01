#ifndef TINC_AVL_TREE_H
#define TINC_AVL_TREE_H

/*
    avl_tree.h -- header file for avl_tree.c
    Copyright (C) 1998 Michael H. Buselli
                  2000-2005 Ivo Timmermans,
                  2000-2006 Guus Sliepen <guus@tinc-vpn.org>
                  2000-2005 Wessel Dankers <wsl@tinc-vpn.org>

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

    Original AVL tree library by Michael H. Buselli <cosine@cosine.org>.

    Modified 2000-11-28 by Wessel Dankers <wsl@tinc-vpn.org> to use counts
    instead of depths, to add the ->next and ->prev and to generally obfuscate
    the code. Mail me if you found a bug.

    Cleaned up and incorporated some of the ideas from the red-black tree
    library for inclusion into tinc (https://www.tinc-vpn.org/) by
    Guus Sliepen <guus@tinc-vpn.org>.
*/

#ifndef AVL_DEPTH
#ifndef AVL_COUNT
#define AVL_DEPTH
#endif
#endif

typedef struct avl_node_t {

	/* Linked list part */

	struct avl_node_t *next;
	struct avl_node_t *prev;

	/* Tree part */

	struct avl_node_t *parent;
	struct avl_node_t *left;
	struct avl_node_t *right;

#ifdef AVL_COUNT
	unsigned int count;
#endif
#ifdef AVL_DEPTH
	unsigned char depth;
#endif

	/* Payload */

	void *data;

} avl_node_t;

typedef int (*avl_compare_t)(const void *data1, const void *data2);
typedef void (*avl_action_t)(const void *data);
typedef void (*avl_action_node_t)(const avl_node_t *node);

typedef struct avl_tree_t {

	/* Linked list part */

	avl_node_t *head;
	avl_node_t *tail;

	/* Tree part */

	avl_node_t *root;

	avl_compare_t compare;
	avl_action_t delete;

} avl_tree_t;

/* (De)constructors */

extern avl_tree_t *avl_alloc_tree(avl_compare_t compare, avl_action_t delete);
extern void avl_free_tree(avl_tree_t *tree);

extern avl_node_t *avl_alloc_node(void);
extern void avl_free_node(avl_tree_t *tree, avl_node_t *node);

/* Insertion and deletion */

extern avl_node_t *avl_insert(avl_tree_t *tree, void *data);
extern avl_node_t *avl_insert_node(avl_tree_t *tree, avl_node_t *node);

extern void avl_insert_top(avl_tree_t *tree, avl_node_t *node);
extern void avl_insert_before(avl_tree_t *tree, avl_node_t *before, avl_node_t *node);
extern void avl_insert_after(avl_tree_t *tree, avl_node_t *after, avl_node_t *node);

extern avl_node_t *avl_unlink(avl_tree_t *tree, void *data);
extern void avl_unlink_node(avl_tree_t *tree, avl_node_t *node);
extern void avl_delete(avl_tree_t *tree, void *data);
extern void avl_delete_node(avl_tree_t *tree, avl_node_t *node);

/* Fast tree cleanup */

extern void avl_delete_tree(avl_tree_t *tree);

/* Searching */

extern void *avl_search(const avl_tree_t *tree, const void *data);
extern void *avl_search_closest(const avl_tree_t *tree, const void *data, int *result);
extern void *avl_search_closest_smaller(const avl_tree_t *tree, const void *data);
extern void *avl_search_closest_greater(const avl_tree_t *tree, const void *data);

extern avl_node_t *avl_search_node(const avl_tree_t *tree, const void *data);
extern avl_node_t *avl_search_closest_node(const avl_tree_t *tree, const void *data, int *result);
extern avl_node_t *avl_search_closest_smaller_node(const avl_tree_t *tree, const void *data);
extern avl_node_t *avl_search_closest_greater_node(const avl_tree_t *tree, const void *data);

/* Tree walking */

extern void avl_foreach(const avl_tree_t *tree, avl_action_t action);
extern void avl_foreach_node(const avl_tree_t *tree, avl_action_t action);

/* Indexing */

#ifdef AVL_COUNT
extern unsigned int avl_count(const avl_tree_t *tree);
extern avl_node_t *avl_get_node(const avl_tree_t *tree, unsigned int index);
extern unsigned int avl_index(const avl_node_t *node);
#endif
#ifdef AVL_DEPTH
extern unsigned int avl_depth(const avl_tree_t *tree);
#endif

#endif
