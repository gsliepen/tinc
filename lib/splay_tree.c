/*
    splay_tree.c -- splay tree and linked list convenience
    Copyright (C) 2004 Guus Sliepen <guus@tinc-vpn.org>

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

    $Id: splay_tree.c 1374 2004-03-21 14:21:22Z guus $
*/

#include "system.h"

#include "splay_tree.h"
#include "xalloc.h"

/* Splay operation */

static splay_node_t *splay_top_down(splay_tree_t *tree, const void *data, int *result) {
	splay_node_t left = {0}, right = {0};
	splay_node_t *leftbottom = &left, *rightbottom = &right, *child;
	splay_node_t *node = tree->root;
	int c;

	while((c = tree->compare(data, node->data))) {
		if(c < 0) {
			child = node->left;

			if(child) {
				c = tree->compare(data, child->data);
				
				if(c < 0) {
					rightbottom->left = child;
					child->parent = rightbottom;
					rightbottom = child;

					node->left = child->right;
					child->right = node;
					node->parent = child;
					node = child->left;
					child->left = NULL;
				} else if (c > 0) {
					if(!child->right)
						break;

					leftbottom->right = child;
					child->parent = leftbottom;
					leftbottom = child;

					rightbottom->left = node;
					node->parent = rightbottom;
					rightbottom = node;

					node->left = NULL;
					node = child->right;
					child->right = NULL;
				} else {
					rightbottom->left = node;
					node->parent = rightbottom;
					rightbottom = node;

					node->left = NULL;
					child->parent = NULL;
					node = child;
					break;
				}
			} else {
				break;
			}
		} else {
			child = node->right;

			if(child) {
				c = tree->compare(data, child->data);
				
				if(c > 0) {
					leftbottom->right = child;
					child->parent = leftbottom;
					leftbottom = child;

					node->right = child->left;
					child->left = node;
					node->parent = child;
					node = child->right;
					child->right = NULL;
				} else if (c < 0) {
					if(!child->left)
						break;

					rightbottom->left = child;
					child->parent = rightbottom;
					rightbottom = child;

					leftbottom->right = node;
					node->parent = leftbottom;
					leftbottom = node;

					node->right = NULL;
					node = child->left;
					child->left = NULL;
				} else {
					leftbottom->right = node;
					node->parent = leftbottom;
					leftbottom = node;

					node->right = NULL;
					child->parent = NULL;
					node = child;
					break;
				}
			} else {
				break;
			}
		}
	}

	tree->root = node;

	/* Merge trees */

	if(left.right) {
		if(node->left) {
			leftbottom->right = node->left;
			node->left->parent = leftbottom;
		}
		node->left = left.right;
		left.right->parent = node;
	}

	if(right.left) {
		if(node->right) {
			rightbottom->left = node->right;
			node->right->parent = rightbottom;
		}
		node->right = right.left;
		right.left->parent = node;
	}

	if(result)
		*result = c;

	return node;
}
				
		
static void splay_bottom_up(splay_tree_t *tree, splay_node_t *node) {
	splay_node_t *parent, *grandparent;

	while(node->parent) {
		parent = node->parent;
		grandparent = node->parent->parent;

		if(!grandparent) { /* zig */
			if(node == parent->left) {
				parent->left = node->right;
				node->right = parent;
			} else {
				parent->right = node->left;
				node->left = parent;
			}

			parent->parent = node;
			node->parent = NULL;
		} else {
			if(node == grandparent->left->left) { /* left zig-zig */
				grandparent->left = parent->right;
				parent->right = grandparent;
				grandparent->parent = parent;

				parent->left = node->right;
				node->right = parent;
				parent->parent = node;

			} else if(node == grandparent->right->right) { /* right zig-zig */
				grandparent->right = parent->left;
				parent->left = grandparent;
				grandparent->parent = parent;

				parent->right = node->left;
				node->left = parent;
				parent->parent = node;

			} else if(node == grandparent->left->right) { /* left-right zig-zag */
				parent->right = node->left;
				node->left = parent;
				parent->parent = node;

				grandparent->left = node->right;
				node->right = grandparent;
				grandparent->parent = node;

			} else { /* right-left zig-zag */
				parent->left = node->right;
				node->right = parent;
				parent->parent = node;

				grandparent->right = node->left;
				node->left = grandparent;
				grandparent->parent = node;
			}

			node->parent = grandparent->parent;

			if(node->parent) {
				if(grandparent == node->parent->left)
					node->parent->left = node;
				else
					node->parent->right = node;
			}
		}
	}

	tree->root = node;
}

/* (De)constructors */

splay_tree_t *splay_alloc_tree(splay_compare_t compare, splay_action_t delete) {
	splay_tree_t *tree;

	tree = xmalloc_and_zero(sizeof(splay_tree_t));
	tree->compare = compare;
	tree->delete = delete;

	return tree;
}

void splay_free_tree(splay_tree_t *tree) {
	free(tree);
}

splay_node_t *splay_alloc_node(void) {
	return xmalloc_and_zero(sizeof(splay_node_t));
}

void splay_free_node(splay_tree_t *tree, splay_node_t *node) {
	if(node->data && tree->delete)
		tree->delete(node->data);

	free(node);
}

/* Searching */

void *splay_search(splay_tree_t *tree, const void *data) {
	splay_node_t *node;

	node = splay_search_node(tree, data);

	return node ? node->data : NULL;
}

void *splay_search_closest(splay_tree_t *tree, const void *data, int *result) {
	splay_node_t *node;

	node = splay_search_closest_node(tree, data, result);

	return node ? node->data : NULL;
}

void *splay_search_closest_smaller(splay_tree_t *tree, const void *data) {
	splay_node_t *node;

	node = splay_search_closest_smaller_node(tree, data);

	return node ? node->data : NULL;
}

void *splay_search_closest_greater(splay_tree_t *tree, const void *data) {
	splay_node_t *node;

	node = splay_search_closest_greater_node(tree, data);

	return node ? node->data : NULL;
}

splay_node_t *splay_search_node(splay_tree_t *tree, const void *data) {
	splay_node_t *node;
	int result;

	node = splay_search_closest_node(tree, data, &result);

	return result ? NULL : node;
}

splay_node_t *splay_search_closest_node_nosplay(const splay_tree_t *tree, const void *data, int *result) {
	splay_node_t *node;
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

splay_node_t *splay_search_closest_node(splay_tree_t *tree, const void *data, int *result) {
	return splay_top_down(tree, data, result);
}

splay_node_t *splay_search_closest_smaller_node(splay_tree_t *tree, const void *data) {
	splay_node_t *node;
	int result;

	node = splay_search_closest_node(tree, data, &result);

	if(result < 0)
		node = node->prev;

	return node;
}

splay_node_t *splay_search_closest_greater_node(splay_tree_t *tree, const void *data) {
	splay_node_t *node;
	int result;

	node = splay_search_closest_node(tree, data, &result);

	if(result > 0)
		node = node->next;

	return node;
}

/* Insertion and deletion */

splay_node_t *splay_insert(splay_tree_t *tree, void *data) {
	splay_node_t *closest, *new;
	int result;

	if(!tree->root) {
		new = splay_alloc_node();
		new->data = data;
		splay_insert_top(tree, new);
	} else {
		closest = splay_search_closest_node_nosplay(tree, data, &result);

		if(!result)
			return NULL;

		new = splay_alloc_node();
		new->data = data;
		
		if(result < 0)
			splay_insert_before(tree, closest, new);
		else
			splay_insert_after(tree, closest, new);
	}			

	return new;
}

splay_node_t *splay_insert_node(splay_tree_t *tree, splay_node_t *node) {
	splay_node_t *closest;
	int result;

	if(!tree->root)
		splay_insert_top(tree, node);
	else {
		closest = splay_search_closest_node_nosplay(tree, node->data, &result);
		
		if(!result)
			return NULL;

		if(result < 0)
			splay_insert_before(tree, closest, node);
		else
			splay_insert_after(tree, closest, node);
	}

	return node;
}

void splay_insert_top(splay_tree_t *tree, splay_node_t *node) {
	node->prev = node->next = node->parent = NULL;
	tree->head = tree->tail = tree->root = node;
}

void splay_insert_before(splay_tree_t *tree, splay_node_t *before, splay_node_t *node) {
	if(!before) {
		if(tree->tail)
			splay_insert_after(tree, tree->tail, node);
		else
			splay_insert_top(tree, node);
		return;
	}

	node->next = before;
	node->parent = before;
	node->prev = before->prev;

	if(before->left) {
		splay_insert_after(tree, before->prev, node);
		return;
	}

	if(before->prev)
		before->prev->next = node;
	else
		tree->head = node;

	before->prev = node;
	before->left = node;

	splay_bottom_up(tree, node);
}

void splay_insert_after(splay_tree_t *tree, splay_node_t *after, splay_node_t *node) {
	if(!after) {
		if(tree->head)
			splay_insert_before(tree, tree->head, node);
		else
			splay_insert_top(tree, node);
		return;
	}

	if(after->right) {
		splay_insert_before(tree, after->next, node);
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

	splay_bottom_up(tree, node);
}

splay_node_t *splay_unlink(splay_tree_t *tree, void *data) {
	splay_node_t *node;
	int result;

	node = splay_search_closest_node_nosplay(tree, data, &result);

	if(node && !result)
		splay_unlink_node(tree, node);

	return node;
}

void splay_unlink_node(splay_tree_t *tree, splay_node_t *node) {
	if(node->prev)
		node->prev->next = node->next;
	else
		tree->head = node->next;

	if(node->next)
		node->next->prev = node->prev;
	else
		tree->tail = node->prev;

	if(node->left) {
		node->left->parent = NULL;
		tree->root = node->left;

		if(node->right) {
			splay_bottom_up(tree, node->prev);
			node->prev->right = node->right;
			node->right->parent = node->prev;
		}
	} else {
		node->right->parent = NULL;
		tree->root = node->right;
	}
}

void splay_delete_node(splay_tree_t *tree, splay_node_t *node) {
	splay_unlink_node(tree, node);
	splay_free_node(tree, node);
}

void splay_delete(splay_tree_t *tree, void *data) {
	splay_node_t *node;

	node = splay_search_node(tree, data);

	if(node)
		splay_delete_node(tree, node);
}

/* Fast tree cleanup */

void splay_delete_tree(splay_tree_t *tree) {
	splay_node_t *node, *next;

	for(node = tree->root; node; node = next) {
		next = node->next;
		splay_free_node(tree, node);
	}

	splay_free_tree(tree);
}

/* Tree walking */

void splay_foreach(const splay_tree_t *tree, splay_action_t action) {
	splay_node_t *node, *next;

	for(node = tree->head; node; node = next) {
		next = node->next;
		action(node->data);
	}
}

void splay_foreach_node(const splay_tree_t *tree, splay_action_t action) {
	splay_node_t *node, *next;

	for(node = tree->head; node; node = next) {
		next = node->next;
		action(node);
	}
}
