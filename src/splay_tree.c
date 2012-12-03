/*
    splay_tree.c -- splay tree and linked list convenience
    Copyright (C) 2004-2012 Guus Sliepen <guus@tinc-vpn.org>

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

#include "splay_tree.h"
#include "xalloc.h"

/* Splay operation */

static splay_node_t *splay_top_down(splay_tree_t *tree, const void *data, int *result) {
	splay_node_t left = {NULL}, right = {NULL};
	splay_node_t *leftbottom = &left, *rightbottom = &right, *child, *grandchild;
	splay_node_t *root = tree->root;
	int c;

	if(!root) {
		if(result)
			*result = 0;
		return NULL;
	}

	while((c = tree->compare(data, root->data))) {
		if(c < 0 && (child = root->left)) {
			c = tree->compare(data, child->data);

			if(c < 0 && (grandchild = child->left)) {
				rightbottom->left = child;
				child->parent = rightbottom;
				rightbottom = child;

				if((root->left = child->right))
					child->right->parent = root;

				child->right = root;
				root->parent = child;

				child->left = NULL;
				grandchild->parent = NULL;

				root = grandchild;
			} else if (c > 0 && (grandchild = child->right)) {
				leftbottom->right = child;
				child->parent = leftbottom;
				leftbottom = child;

				child->right = NULL;
				grandchild->parent = NULL;

				rightbottom->left = root;
				root->parent = rightbottom;
				rightbottom = root;

				root->left = NULL;

				root = grandchild;
			} else {
				rightbottom->left = root;
				root->parent = rightbottom;
				rightbottom = root;

				root->left = NULL;
				child->parent = NULL;

				root = child;
				break;
			}
		} else if(c > 0 && (child = root->right)) {
			c = tree->compare(data, child->data);

			if(c > 0 && (grandchild = child->right)) {
				leftbottom->right = child;
				child->parent = leftbottom;
				leftbottom = child;

				if((root->right = child->left))
					child->left->parent = root;

				child->left = root;
				root->parent = child;

				child->right = NULL;
				grandchild->parent = NULL;

				root = grandchild;
			} else if (c < 0 && (grandchild = child->left)) {
				rightbottom->left = child;
				child->parent = rightbottom;
				rightbottom = child;

				child->left = NULL;
				grandchild->parent = NULL;

				leftbottom->right = root;
				root->parent = leftbottom;
				leftbottom = root;

				root->right = NULL;

				root = grandchild;
			} else {
				leftbottom->right = root;
				root->parent = leftbottom;
				leftbottom = root;

				root->right = NULL;
				child->parent = NULL;

				root = child;
				break;
			}
		} else {
			break;
		}
	}

	/* Merge trees */

	if(left.right) {
		if(root->left) {
			leftbottom->right = root->left;
			root->left->parent = leftbottom;
		}
		root->left = left.right;
		left.right->parent = root;
	}

	if(right.left) {
		if(root->right) {
			rightbottom->left = root->right;
			root->right->parent = rightbottom;
		}
		root->right = right.left;
		right.left->parent = root;
	}

	/* Return result */

	tree->root = root;
	if(result)
		*result = c;

	return tree->root;
}

static void splay_bottom_up(splay_tree_t *tree, splay_node_t *node) {
	splay_node_t *parent, *grandparent, *greatgrandparent;

	while((parent = node->parent)) {
		if(!(grandparent = parent->parent)) { /* zig */
			if(node == parent->left) {
				if((parent->left = node->right))
					parent->left->parent = parent;
				node->right = parent;
			} else {
				if((parent->right = node->left))
					parent->right->parent = parent;
				node->left = parent;
			}

			parent->parent = node;
			node->parent = NULL;
		} else {
			greatgrandparent = grandparent->parent;

			if(node == parent->left && parent == grandparent->left) { /* left zig-zig */
				if((grandparent->left = parent->right))
					grandparent->left->parent = grandparent;
				parent->right = grandparent;
				grandparent->parent = parent;

				if((parent->left = node->right))
					parent->left->parent = parent;
				node->right = parent;
				parent->parent = node;
			} else if(node == parent->right && parent == grandparent->right) { /* right zig-zig */
				if((grandparent->right = parent->left))
					grandparent->right->parent = grandparent;
				parent->left = grandparent;
				grandparent->parent = parent;

				if((parent->right = node->left))
					parent->right->parent = parent;
				node->left = parent;
				parent->parent = node;
			} else if(node == parent->right && parent == grandparent->left) { /* left-right zig-zag */
				if((parent->right = node->left))
					parent->right->parent = parent;
				node->left = parent;
				parent->parent = node;

				if((grandparent->left = node->right))
					grandparent->left->parent = grandparent;
				node->right = grandparent;
				grandparent->parent = node;
			} else { /* right-left zig-zag */
				if((parent->left = node->right))
					parent->left->parent = parent;
				node->right = parent;
				parent->parent = node;

				if((grandparent->right = node->left))
					grandparent->right->parent = grandparent;
				node->left = grandparent;
				grandparent->parent = node;
			}

			if((node->parent = greatgrandparent)) {
				if(grandparent == greatgrandparent->left)
					greatgrandparent->left = node;
				else
					greatgrandparent->right = node;
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
			else
				break;
		} else if(c > 0) {
			if(node->right)
				node = node->right;
			else
				break;
		} else {
			break;
		}
	}

	if(result)
		*result = c;
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
		closest = splay_search_closest_node(tree, data, &result);

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

	node->left = node->right = node->parent = node->next = node->prev = NULL;

	if(!tree->root)
		splay_insert_top(tree, node);
	else {
		closest = splay_search_closest_node(tree, node->data, &result);

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
	node->prev = node->next = node->left = node->right = node->parent = NULL;
	tree->head = tree->tail = tree->root = node;
	tree->count++;
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
	if((node->prev = before->prev))
		before->prev->next = node;
	else
		tree->head = node;
	before->prev = node;

	splay_bottom_up(tree, before);

	node->right = before;
	before->parent = node;
	if((node->left = before->left))
		before->left->parent = node;
	before->left = NULL;

	node->parent = NULL;
	tree->root = node;
	tree->count++;
}

void splay_insert_after(splay_tree_t *tree, splay_node_t *after, splay_node_t *node) {
	if(!after) {
		if(tree->head)
			splay_insert_before(tree, tree->head, node);
		else
			splay_insert_top(tree, node);
		return;
	}

	node->prev = after;
	if((node->next = after->next))
		after->next->prev = node;
	else
		tree->tail = node;
	after->next = node;

	splay_bottom_up(tree, after);

	node->left = after;
	after->parent = node;
	if((node->right = after->right))
		after->right->parent = node;
	after->right = NULL;

	node->parent = NULL;
	tree->root = node;
	tree->count++;
}

splay_node_t *splay_unlink(splay_tree_t *tree, void *data) {
	splay_node_t *node;

	node = splay_search_node(tree, data);

	if(node)
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

	splay_bottom_up(tree, node);

	if(node->prev) {
		node->left->parent = NULL;
		tree->root = node->left;
		if((node->prev->right = node->right))
			node->right->parent = node->prev;
	} else if(node->next) {
		tree->root = node->right;
		node->right->parent = NULL;
	} else {
		tree->root = NULL;
	}

	tree->count--;
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
	for(splay_node_t *node = tree->head, *next; node; node = next) {
		next = node->next;
		splay_free_node(tree, node);
	}

	splay_free_tree(tree);
}

/* Tree walking */

void splay_foreach(const splay_tree_t *tree, splay_action_t action) {
	for(splay_node_t *node = tree->head, *next; node; node = next) {
		next = node->next;
		action(node->data);
	}
}

void splay_foreach_node(const splay_tree_t *tree, splay_action_t action) {
	for(splay_node_t *node = tree->head, *next; node; node = next) {
		next = node->next;
		action(node);
	}
}
