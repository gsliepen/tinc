/*
    rbl.c -- red-black tree + linked list convenience
    Copyright (C) 2000 Ivo Timmermans <ivo@o2w.nl>,
                  2000 Guus Sliepen <guus@sliepen.eu.org>

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

    $Id: rbl.c,v 1.1.2.13 2002/06/21 10:11:11 guus Exp $
*/

#include "config.h"

#include <stdlib.h>
#include <xalloc.h>

#include "rbl.h"
#include <system.h>

/* Allocate a new rbl node */
rbl_t *new_rbl()
{
  return (rbl_t *)xmalloc_and_zero(sizeof(rbl_t));
}

/* Free a rbl node */
void free_rbl(rbl_t *rbl)
{
  if(rbl->data && rbl->tree->delete)
    rbl->tree->delete(rbl->data);
  free(rbl);
}

/* Allocate a new rbltree header */
rbltree_t *new_rbltree(rbl_compare_t compare, rbl_action_t delete)
{
  rbltree_t *tree;

  tree = (rbltree_t *)xmalloc_and_zero(sizeof(rbltree_t));
  if(tree)
    {
      tree->compare = compare;
      tree->delete = delete;
    }
  
  return tree;
}

/* Free a rbltree header */
void free_rbltree(rbltree_t *tree)
{
  free(tree);
}

/* Search closest match in the tree */
rbl_t *rbl_search_closest_rbl(rbltree_t *tree, void *data)
{
  rbl_t *rbl, *next;
  int result;

  next = rbl = tree->top;
  
  while(next)
    {
      rbl = next;
      
      result = tree->compare(data, rbl->data);

      if(result < 0)
        next = rbl->left;
      else if(result > 0)
        next = rbl->right;
      else
        break;
    }
    
  return rbl;
}

/* Search closest match in the tree */
rbl_t *rbl_search_closest_greater_rbl(rbltree_t *tree, void *data)
{
  rbl_t *rbl;

  rbl = rbl_search_closest_rbl(tree, data);

  if(rbl)
    {
      if(tree->compare(data, rbl->data) > 0)
        rbl = rbl->next;
    }
    
  return rbl;
}

/* Search closest match in the tree */
rbl_t *rbl_search_closest_smaller_rbl(rbltree_t *tree, void *data)
{
  rbl_t *rbl;

  rbl = rbl_search_closest_rbl(tree, data);

  if(rbl)
    {
      if(tree->compare(data, rbl->data) < 0)
        rbl = rbl->next;
    }
    
  return rbl;
}

void *rbl_search_closest(rbltree_t *tree, void *data)
{
  rbl_t *rbl;
  
  rbl = rbl_search_closest_rbl(tree, data);

  if(rbl)
    return rbl->data;
  else
    return NULL;
}

void *rbl_search_closest_greater(rbltree_t *tree, void *data)
{
  rbl_t *rbl;
  
  rbl = rbl_search_closest_greater_rbl(tree, data);

  if(rbl)
    return rbl->data;
  else
    return NULL;
}

void *rbl_search_closest_smaller(rbltree_t *tree, void *data)
{
  rbl_t *rbl;
  
  rbl = rbl_search_closest_smaller_rbl(tree, data);

  if(rbl)
    return rbl->data;
  else
    return NULL;
}

/* Search exact match or return NULL pointer */
rbl_t *rbl_search_rbl(rbltree_t *tree, void *data)
{
  rbl_t *rbl;
  int result;

  rbl = tree->top;
  
  while(rbl)
    {
      result = tree->compare(data, rbl->data);

      if(result < 0)
        rbl = rbl->left;
      else if(result > 0)
        rbl = rbl->right;
      else
        return rbl;
    }

  return NULL;
}

void *rbl_search(rbltree_t *tree, void *data)
{
  rbl_t *rbl;

  rbl = rbl_search_rbl(tree, data);

  if(rbl)
    return rbl->data;
  else
    return NULL;  
}

/* Red-black tree operations taken from Introduction to Algorithms,
   Cormen, Leiserson & Rivest, chapter 14.
*/

void rbl_left_rotate(rbl_t *x)
{
  rbl_t *y;
  
  y = x->right;
  x->right = y->left;

  if(y->left)
    y->left->parent = x;

  y->parent = x->parent;
  
  if(!x->parent)
    x->tree->top = y;
  else
    if(x == x->parent->left)
      x->parent->left = y;
    else
      x->parent->right = y;

  y->left = x;
  x->parent = y;      
}

void rbl_right_rotate(rbl_t *y)
{
  rbl_t *x;

  x = y->left;
  y->left = x->right;

  if(x->right)
    x->right->parent = y;

  x->parent = y->parent;
  
  if(!y->parent)
    y->tree->top = x;
  else
    if(y == y->parent->right)
      y->parent->right = x;
    else
      y->parent->left = x;
  
  x->right = y;
  y->parent = x;      
}

/* Insert a node into the rbl tree */
rbl_t *rbl_insert_rbl(rbltree_t *tree, rbl_t *rbl)
{
  rbl_t *closest, *x, *y;
  int result;
  
  rbl->tree = tree;

  /* Binary tree and linked list insert */
  
  if(tree->top)
    {
      closest = rbl_search_closest_rbl(tree, rbl->data);
      result = tree->compare(rbl->data, closest->data);
      if(result < 0)
        {
          closest->left = rbl;

          rbl->prev = closest->prev;
          rbl->next = closest;
          closest->prev = rbl;

          if(rbl->prev)
            rbl->prev->next = rbl;
          else
            tree->head = rbl;
        }
      else if(result > 0)
        {
          closest->right = rbl;

          rbl->next = closest->next;
          rbl->prev = closest;
          closest->next = rbl;

          if(rbl->next)
            rbl->next->prev = rbl;
          else
            tree->tail = rbl;
        }
      else
        return closest;		/* Ofcourse, we cannot add two identical things */

      rbl->parent = closest;
    }
  else
    {
      tree->top = rbl;
      tree->head = rbl;
      tree->tail = rbl;
    }

  /* Red-black part of insert */
  
  x = rbl;
  x->color = RBL_RED;
  
  while(x != tree->top && x->parent->color == RBL_RED)
    {
      if(x->parent == x->parent->parent->left)
        {
          y = x->parent->parent->right;
          if(y && y->color == RBL_RED)
            {
              x->parent->color = RBL_BLACK;
              y->color = RBL_BLACK;
              x->parent->parent->color = RBL_RED;
              x = x->parent->parent;
            }
          else          
            {
              if(x == x->parent->right)
                {
                  x = x->parent;
                  rbl_left_rotate(x);
                }
              x->parent->color = RBL_BLACK;
              x->parent->parent->color = RBL_RED;
              rbl_right_rotate(x->parent->parent);
            }
        }
      else
        {
          y = x->parent->parent->left;
          if(y && y->color == RBL_RED)
            {
              x->parent->color = RBL_BLACK;
              y->color = RBL_BLACK;
              x->parent->parent->color = RBL_RED;
              x = x->parent->parent;
            }
          else          
            {
              if(x == x->parent->left)
                {
                  x = x->parent;
                  rbl_right_rotate(x);
                }
              x->parent->color = RBL_BLACK;
              x->parent->parent->color = RBL_RED;
              rbl_left_rotate(x->parent->parent);
            }
        }
    }
  
  tree->top->color = RBL_BLACK;
  return rbl;
}

/* Create a new node and insert it into the tree */
rbl_t *rbl_insert(rbltree_t *tree, void *data)
{
  rbl_t *rbl;
  
  rbl = new_rbl();
  rbl->data = data;

  if(rbl_insert_rbl(tree, rbl) == rbl)
    return rbl;
  else
    {
      free_rbl(rbl);
      return NULL;
    }
}

/* Restore red-black property after violation due to a deletion */
void rbl_delete_fixup(rbl_t *x)
{
  rbl_t *w;
  
  while(x != x->tree->top && x->color == RBL_BLACK)
    {
      if(x == x->parent->left)
        {
          w = x->parent->right;
          if(w->color == RBL_RED)
            {
              w->color = RBL_BLACK;
              x->parent->color = RBL_RED;
              rbl_left_rotate(x->parent);
              w = x->parent->right;
            }
          if(w->left->color == RBL_BLACK && w->right->color == RBL_BLACK)
            {
              w->color = RBL_RED;
              x = x->parent;
            }
          else
            {
              if(w->right->color == RBL_BLACK)
                {
                  w->left->color = RBL_BLACK;
                  w->color = RBL_RED;
                  rbl_right_rotate(w);
                  w = x->parent->right;
                }
              w->color = x->parent->color;
              x->parent->color = RBL_BLACK;
              w->right->color = RBL_BLACK;
              rbl_left_rotate(x->parent);
              x = x->tree->top;
            }
        }
      else
        {
          w = x->parent->left;
          if(w->color == RBL_RED)
            {
              w->color = RBL_BLACK;
              x->parent->color = RBL_RED;
              rbl_right_rotate(x->parent);
              w = x->parent->left;
            }
          if(w->right->color == RBL_BLACK && w->left->color == RBL_BLACK)
            {
              w->color = RBL_RED;
              x = x->parent;
            }
          else
            {
              if(w->left->color == RBL_BLACK)
                {
                  w->right->color = RBL_BLACK;
                  w->color = RBL_RED;
                  rbl_left_rotate(w);
                  w = x->parent->left;
                }
              w->color = x->parent->color;
              x->parent->color = RBL_BLACK;
              w->left->color = RBL_BLACK;
              rbl_right_rotate(x->parent);
              x = x->tree->top;
            }
        }
    }
  
  x->color = RBL_BLACK;
}

/* Unlink node from the tree, but keep the node intact. */
rbl_t *rbl_unlink_rbl(rbl_t *rbl)
{
  rbl_t *x, *y;

  /* Binary tree delete */

  if(rbl->left && rbl->right)
    y = rbl->next;
  else
    y = rbl;
    
  if(y->left)
    x = y->left;
  else
    x = y->right;
    
  if(x)
    x->parent = y->parent;
    
  if(!y->parent)
    rbl->tree->top = x;
  else
    if(y == y->parent->left)
      y->parent->left = x;
    else
      y->parent->right = x;
  
  if(y != rbl)
    {
      y->left = rbl->left;
      y->right = rbl->right;
      y->parent = rbl->parent;
      if(rbl == rbl->parent->left)
        rbl->parent->left = y;
      else
        rbl->parent->right = y;
    }

  /* Linked list delete */
  
  if(rbl->prev)
    rbl->prev->next = rbl->next;
  else
    rbl->tree->head = rbl->next;
  
  if(rbl->next)
    rbl->next->prev = rbl->prev;
  else
    rbl->tree->tail = rbl->prev;

  /* Red-black part of delete */
  
  if(y->color == RBL_BLACK && x)
    rbl_delete_fixup(x);

  return rbl;
}

/* Search node in tree and unlink it */
rbl_t *rbl_unlink(rbltree_t *tree, void *data)
{
  rbl_t *rbl;
  
  rbl = rbl_search_rbl(tree, data);
  
  if(rbl)
    rbl_unlink_rbl(rbl);

  return rbl;
}

/* Unlink node and free it */
void rbl_delete_rbl(rbl_t *rbl)
{
  rbl_unlink_rbl(rbl);
  free_rbl(rbl);
}

/* Search node in tree, unlink and free it */
void rbl_delete(rbltree_t *tree, void *data)
{
  rbl_t *rbl;

  rbl = rbl_unlink(tree, data);

  if(rbl)
    free_rbl(rbl);
}

/* Optimized unlinking for a complete tree */
void rbl_unlink_rbltree(rbltree_t *tree)
{
  rbl_t *rbl, *next;
  
  for(rbl = tree->head; rbl; rbl = next)
    {
      next = rbl->next;
      rbl->tree = NULL;
      rbl->parent = NULL;
      rbl->left = NULL;
      rbl->right = NULL;
      rbl->prev = NULL;
      rbl->next = NULL;
    }
    
  tree->top = NULL;
  tree->head = NULL;
  tree->tail = NULL;
}

/* Optimized deletion for a complete tree */
void rbl_delete_rbltree(rbltree_t *tree)
{
  rbl_t *rbl, *next;
  
  for(rbl = tree->head; rbl; rbl = next)
    {
      next = rbl->next;
      free_rbl(rbl);
    }

  tree->top = NULL;
  tree->head = NULL;
  tree->tail = NULL;
}

/* Do action for each list entry (in order)
   Deletion of entry for which action is called is allowed.
 */
void rbl_foreach(rbltree_t *tree, rbl_action_t action)
{
  rbl_t *rbl, *next;
  
  for(rbl = tree->head; rbl; rbl = next)
    {
      next = rbl->next;
      action(rbl->data);
    }
}

void rbl_foreach_rbl(rbltree_t *tree, rbl_action_rbl_t action)
{
  rbl_t *rbl, *next;
  
  for(rbl = tree->head; rbl; rbl = next)
    {
      next = rbl->next;
      action(rbl);
    }
}
