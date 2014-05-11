/*
    avl_tree.c -- avl_ tree and linked list convenience
    Copyright (C) 1998 Michael H. Buselli
                  2000-2005 Ivo Timmermans,
                  2000-2014 Guus Sliepen <guus@tinc-vpn.org>
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
    library for inclusion into tinc (http://www.tinc-vpn.org/) by
    Guus Sliepen <guus@tinc-vpn.org>.
*/

#include "system.h"

#include "avl_tree.h"
#include "xalloc.h"

#ifdef AVL_COUNT
#define AVL_NODE_COUNT(n)  ((n) ? (n)->count : 0)
#define AVL_L_COUNT(n)     (AVL_NODE_COUNT((n)->left))
#define AVL_R_COUNT(n)     (AVL_NODE_COUNT((n)->right))
#define AVL_CALC_COUNT(n)  (AVL_L_COUNT(n) + AVL_R_COUNT(n) + 1)
#endif

#ifdef AVL_DEPTH
#define AVL_NODE_DEPTH(n)  ((n) ? (n)->depth : 0)
#define L_AVL_DEPTH(n)     (AVL_NODE_DEPTH((n)->left))
#define R_AVL_DEPTH(n)     (AVL_NODE_DEPTH((n)->right))
#define AVL_CALC_DEPTH(n)  ((L_AVL_DEPTH(n)>R_AVL_DEPTH(n)?L_AVL_DEPTH(n):R_AVL_DEPTH(n)) + 1)
#endif

#ifndef AVL_DEPTH
static int lg(unsigned int u) __attribute__ ((__const__));

static int lg(unsigned int u)
{
	int r = 1;

	if(!u)
		return 0;

	if(u & 0xffff0000) {
		u >>= 16;
		r += 16;
	}

	if(u & 0x0000ff00) {
		u >>= 8;
		r += 8;
	}

	if(u & 0x000000f0) {
		u >>= 4;
		r += 4;
	}

	if(u & 0x0000000c) {
		u >>= 2;
		r += 2;
	}

	if(u & 0x00000002)
		r++;

	return r;
}
#endif

/* Internal helper functions */

static int avl_check_balance(const avl_node_t *node)
{
#ifdef AVL_DEPTH
	int d;

	d = R_AVL_DEPTH(node) - L_AVL_DEPTH(node);

	return d < -1 ? -1 : d > 1 ? 1 : 0;
#else
/*      int d;
 *      d = lg(AVL_R_COUNT(node)) - lg(AVL_L_COUNT(node));
 *      d = d<-1?-1:d>1?1:0;
 */
	int pl, r;

	pl = lg(AVL_L_COUNT(node));
	r = AVL_R_COUNT(node);

	if(r >> pl + 1)
		return 1;

	if(pl < 2 || r >> pl - 2)
		return 0;

	return -1;
#endif
}

static void avl_rebalance(avl_tree_t *tree, avl_node_t *node)
{
	avl_node_t *child;
	avl_node_t *gchild;
	avl_node_t *parent;
	avl_node_t **superparent;

	parent = node;

	while(node) {
		parent = node->parent;

		superparent =
			parent ? node ==
			parent->left ? &parent->left : &parent->right : &tree->root;

		switch (avl_check_balance(node)) {
			case -1:
				child = node->left;
#ifdef AVL_DEPTH
				if(L_AVL_DEPTH(child) >= R_AVL_DEPTH(child)) {
#else
				if(AVL_L_COUNT(child) >= AVL_R_COUNT(child)) {
#endif
					node->left = child->right;
					if(node->left)
						node->left->parent = node;

					child->right = node;
					node->parent = child;
					*superparent = child;
					child->parent = parent;
#ifdef AVL_COUNT
					node->count = AVL_CALC_COUNT(node);
					child->count = AVL_CALC_COUNT(child);
#endif
#ifdef AVL_DEPTH
					node->depth = AVL_CALC_DEPTH(node);
					child->depth = AVL_CALC_DEPTH(child);
#endif
				} else {
					gchild = child->right;
					node->left = gchild->right;

					if(node->left)
						node->left->parent = node;
					child->right = gchild->left;

					if(child->right)
						child->right->parent = child;
					gchild->right = node;

					gchild->right->parent = gchild;
					gchild->left = child;

					gchild->left->parent = gchild;

					*superparent = gchild;
					gchild->parent = parent;
#ifdef AVL_COUNT
					node->count = AVL_CALC_COUNT(node);
					child->count = AVL_CALC_COUNT(child);
					gchild->count = AVL_CALC_COUNT(gchild);
#endif
#ifdef AVL_DEPTH
					node->depth = AVL_CALC_DEPTH(node);
					child->depth = AVL_CALC_DEPTH(child);
					gchild->depth = AVL_CALC_DEPTH(gchild);
#endif
				}
				break;

			case 1:
				child = node->right;
#ifdef AVL_DEPTH
				if(R_AVL_DEPTH(child) >= L_AVL_DEPTH(child)) {
#else
				if(AVL_R_COUNT(child) >= AVL_L_COUNT(child)) {
#endif
					node->right = child->left;
					if(node->right)
						node->right->parent = node;
					child->left = node;
					node->parent = child;
					*superparent = child;
					child->parent = parent;
#ifdef AVL_COUNT
					node->count = AVL_CALC_COUNT(node);
					child->count = AVL_CALC_COUNT(child);
#endif
#ifdef AVL_DEPTH
					node->depth = AVL_CALC_DEPTH(node);
					child->depth = AVL_CALC_DEPTH(child);
#endif
				} else {
					gchild = child->left;
					node->right = gchild->left;

					if(node->right)
						node->right->parent = node;
					child->left = gchild->right;

					if(child->left)
						child->left->parent = child;
					gchild->left = node;

					gchild->left->parent = gchild;
					gchild->right = child;

					gchild->right->parent = gchild;

					*superparent = gchild;
					gchild->parent = parent;
#ifdef AVL_COUNT
					node->count = AVL_CALC_COUNT(node);
					child->count = AVL_CALC_COUNT(child);
					gchild->count = AVL_CALC_COUNT(gchild);
#endif
#ifdef AVL_DEPTH
					node->depth = AVL_CALC_DEPTH(node);
					child->depth = AVL_CALC_DEPTH(child);
					gchild->depth = AVL_CALC_DEPTH(gchild);
#endif
				}
				break;

			default:
#ifdef AVL_COUNT
				node->count = AVL_CALC_COUNT(node);
#endif
#ifdef AVL_DEPTH
				node->depth = AVL_CALC_DEPTH(node);
#endif
		}
		node = parent;
	}
}

/* (De)constructors */

avl_tree_t *avl_alloc_tree(avl_compare_t compare, avl_action_t delete)
{
	avl_tree_t *tree;

	tree = xmalloc_and_zero(sizeof(avl_tree_t));
	tree->compare = compare;
	tree->delete = delete;

	return tree;
}

void avl_free_tree(avl_tree_t *tree)
{
	free(tree);
}

avl_node_t *avl_alloc_node(void)
{
	return xmalloc_and_zero(sizeof(avl_node_t));
}

void avl_free_node(avl_tree_t *tree, avl_node_t *node)
{
	if(node->data && tree->delete)
		tree->delete(node->data);

	free(node);
}

/* Searching */

void *avl_search(const avl_tree_t *tree, const void *data)
{
	avl_node_t *node;

	node = avl_search_node(tree, data);

	return node ? node->data : NULL;
}

void *avl_search_closest(const avl_tree_t *tree, const void *data, int *result)
{
	avl_node_t *node;

	node = avl_search_closest_node(tree, data, result);

	return node ? node->data : NULL;
}

void *avl_search_closest_smaller(const avl_tree_t *tree, const void *data)
{
	avl_node_t *node;

	node = avl_search_closest_smaller_node(tree, data);

	return node ? node->data : NULL;
}

void *avl_search_closest_greater(const avl_tree_t *tree, const void *data)
{
	avl_node_t *node;

	node = avl_search_closest_greater_node(tree, data);

	return node ? node->data : NULL;
}

avl_node_t *avl_search_node(const avl_tree_t *tree, const void *data)
{
	avl_node_t *node;
	int result;

	node = avl_search_closest_node(tree, data, &result);

	return result ? NULL : node;
}

avl_node_t *avl_search_closest_node(const avl_tree_t *tree, const void *data,
									int *result)
{
	avl_node_t *node;
	int c;

	node = tree->root;

	if(!node) {
		if(result)
			*result = 0;
		return NULL;
	}

	for(;;) {
		c = tree->compare(data, node->data);

		if(c < 0) {
			if(node->left)
				node = node->left;
			else {
				if(result)
					*result = -1;
				break;
			}
		} else if(c > 0) {
			if(node->right)
				node = node->right;
			else {
				if(result)
					*result = 1;
				break;
			}
		} else {
			if(result)
				*result = 0;
			break;
		}
	}

	return node;
}

avl_node_t *avl_search_closest_smaller_node(const avl_tree_t *tree,
											const void *data)
{
	avl_node_t *node;
	int result;

	node = avl_search_closest_node(tree, data, &result);

	if(result < 0)
		node = node->prev;

	return node;
}

avl_node_t *avl_search_closest_greater_node(const avl_tree_t *tree,
											const void *data)
{
	avl_node_t *node;
	int result;

	node = avl_search_closest_node(tree, data, &result);

	if(result > 0)
		node = node->next;

	return node;
}

/* Insertion and deletion */

avl_node_t *avl_insert(avl_tree_t *tree, void *data)
{
	avl_node_t *closest, *new;
	int result;

	if(!tree->root) {
		new = avl_alloc_node();
		new->data = data;
		avl_insert_top(tree, new);
	} else {
		closest = avl_search_closest_node(tree, data, &result);

		switch (result) {
			case -1:
				new = avl_alloc_node();
				new->data = data;
				avl_insert_before(tree, closest, new);
				break;

			case 1:
				new = avl_alloc_node();
				new->data = data;
				avl_insert_after(tree, closest, new);
				break;

			default:
				return NULL;
		}
	}

#ifdef AVL_COUNT
	new->count = 1;
#endif
#ifdef AVL_DEPTH
	new->depth = 1;
#endif

	return new;
}

avl_node_t *avl_insert_node(avl_tree_t *tree, avl_node_t *node)
{
	avl_node_t *closest;
	int result;

	if(!tree->root)
		avl_insert_top(tree, node);
	else {
		closest = avl_search_closest_node(tree, node->data, &result);

		switch (result) {
			case -1:
				avl_insert_before(tree, closest, node);
				break;

			case 1:
				avl_insert_after(tree, closest, node);
				break;

			case 0:
				return NULL;
		}
	}

#ifdef AVL_COUNT
	node->count = 1;
#endif
#ifdef AVL_DEPTH
	node->depth = 1;
#endif

	return node;
}

void avl_insert_top(avl_tree_t *tree, avl_node_t *node)
{
	node->prev = node->next = node->parent = NULL;
	tree->head = tree->tail = tree->root = node;
}

void avl_insert_before(avl_tree_t *tree, avl_node_t *before,
					   avl_node_t *node)
{
	if(!before) {
		if(tree->tail)
			avl_insert_after(tree, tree->tail, node);
		else
			avl_insert_top(tree, node);
		return;
	}

	node->next = before;
	node->parent = before;
	node->prev = before->prev;

	if(before->left) {
		avl_insert_after(tree, before->prev, node);
		return;
	}

	if(before->prev)
		before->prev->next = node;
	else
		tree->head = node;

	before->prev = node;
	before->left = node;

	avl_rebalance(tree, before);
}

void avl_insert_after(avl_tree_t *tree, avl_node_t *after, avl_node_t *node)
{
	if(!after) {
		if(tree->head)
			avl_insert_before(tree, tree->head, node);
		else
			avl_insert_top(tree, node);
		return;
	}

	if(after->right) {
		avl_insert_before(tree, after->next, node);
		return;
	}

	node->prev = after;
	node->parent = after;
	node->next = after->next;

	if(after->next)
		after->next->prev = node;
	else
		tree->tail = node;

	after->next = node;
	after->right = node;

	avl_rebalance(tree, after);
}

avl_node_t *avl_unlink(avl_tree_t *tree, void *data)
{
	avl_node_t *node;

	node = avl_search_node(tree, data);

	if(node)
		avl_unlink_node(tree, node);

	return node;
}

void avl_unlink_node(avl_tree_t *tree, avl_node_t *node)
{
	avl_node_t *parent;
	avl_node_t **superparent;
	avl_node_t *subst, *left, *right;
	avl_node_t *balnode;

	if(node->prev)
		node->prev->next = node->next;
	else
		tree->head = node->next;
	if(node->next)
		node->next->prev = node->prev;
	else
		tree->tail = node->prev;

	parent = node->parent;

	superparent =
		parent ? node ==
		parent->left ? &parent->left : &parent->right : &tree->root;

	left = node->left;
	right = node->right;
	if(!left) {
		*superparent = right;

		if(right)
			right->parent = parent;

		balnode = parent;
	} else if(!right) {
		*superparent = left;
		left->parent = parent;
		balnode = parent;
	} else {
		subst = node->prev;
		if(!subst) // This only happens if node is not actually in a tree at all.
			abort();

		if(subst == left) {
			balnode = subst;
		} else {
			balnode = subst->parent;
			balnode->right = subst->left;

			if(balnode->right)
				balnode->right->parent = balnode;

			subst->left = left;
			left->parent = subst;
		}

		subst->right = right;
		subst->parent = parent;
		right->parent = subst;
		*superparent = subst;
	}

	avl_rebalance(tree, balnode);

	node->next = node->prev = node->parent = node->left = node->right = NULL;

#ifdef AVL_COUNT
	node->count = 0;
#endif
#ifdef AVL_DEPTH
	node->depth = 0;
#endif
}

void avl_delete_node(avl_tree_t *tree, avl_node_t *node)
{
	avl_unlink_node(tree, node);
	avl_free_node(tree, node);
}

void avl_delete(avl_tree_t *tree, void *data)
{
	avl_node_t *node;

	node = avl_search_node(tree, data);

	if(node)
		avl_delete_node(tree, node);
}

/* Fast tree cleanup */

void avl_delete_tree(avl_tree_t *tree)
{
	avl_node_t *node, *next;

	for(node = tree->head; node; node = next) {
		next = node->next;
		avl_free_node(tree, node);
	}

	avl_free_tree(tree);
}

/* Tree walking */

void avl_foreach(const avl_tree_t *tree, avl_action_t action)
{
	avl_node_t *node, *next;

	for(node = tree->head; node; node = next) {
		next = node->next;
		action(node->data);
	}
}

void avl_foreach_node(const avl_tree_t *tree, avl_action_t action)
{
	avl_node_t *node, *next;

	for(node = tree->head; node; node = next) {
		next = node->next;
		action(node);
	}
}

/* Indexing */

#ifdef AVL_COUNT
unsigned int avl_count(const avl_tree_t *tree)
{
	return AVL_NODE_COUNT(tree->root);
}

avl_node_t *avl_get_node(const avl_tree_t *tree, unsigned int index)
{
	avl_node_t *node;
	unsigned int c;

	node = tree->root;

	while(node) {
		c = AVL_L_COUNT(node);

		if(index < c) {
			node = node->left;
		} else if(index > c) {
			node = node->right;
			index -= c + 1;
		} else {
			return node;
		}
	}

	return NULL;
}

unsigned int avl_index(const avl_node_t *node)
{
	avl_node_t *next;
	unsigned int index;

	index = AVL_L_COUNT(node);

	while((next = node->parent)) {
		if(node == next->right)
			index += AVL_L_COUNT(next) + 1;
		node = next;
	}

	return index;
}
#endif
#ifdef AVL_DEPTH
unsigned int avl_depth(const avl_tree_t *tree)
{
	return AVL_NODE_DEPTH(tree->root);
}
#endif
