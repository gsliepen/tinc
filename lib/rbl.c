/*
    rbl.c -- red-black tree + linked list convenience
    Copyright (C) 2000 Ivo Timmermans <itimmermans@bigfoot.com>,
                  2000 Guus Sliepen <guus@sliepen.warande.net>

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

    $Id: rbl.c,v 1.1.2.3 2000/11/18 23:21:00 guus Exp $
*/


/* Allocate a new rbl node */
rbl_t *new_rbl()
{
  return (rbl_t *)xmalloc_and_zero(sizeof(*rbl));
}

/* Free a rbl node */
void free_rbl(rbl_t *rbl)
{
  free(rbl);
}

/* Allocate a new rbltree header */
rbltree_t *new_rbltree(rbl_compare_t *compare, rbl_action_t *delete)
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
rbl_t rbl_search_closest(rbltree_t *tree, void *data)
{
  rbl_t *rbl, *next;
  int result;
  
  next = rbl = tree->top;
  
  while(next)
    {
      rbl = next;
      
      result = tree->compare(rbl->data, data);

      if(result < 0)
        next = rbl->left;
      else if(result > 0)
        next = rbl->right;
      else
        break;
    }
    
  return rbl;
}

/* Search exact match or return NULL pointer */
rbl_t rbl_search(rbltree_t *tree, void *data)
{
  rbl_t *rbl, *next;
  int result;
  
  next = rbl = tree->top;
  
  while(next)
    {
      rbl = next;
      
      result = tree->compare(rbl->data, data);

      if(result < 0)
        next = rbl->left;
      else if(result > 0)
        next = rbl->right;
      else
        return rbl;
    }
    
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
rbl_t rbl_insert_rbl(rbltree_t *tree, rbl_t *rbl)
{
   rbl_t *closest, y;
   int result;
  
  /* Binary tree and linked list insert */
  
  if(tree->top)
    {
      closest = rbl_search_closest(tree, rbl->data);
      result = tree->compare(rbl->data, data);
      if(result < 0)
        {
          closest->left = rbl;
          rbl->prev = closest->prev;
          rbl->next = closest;
          closest->prev = rbl;
          rbl->prev->next = rbl;
        }
      else if(result > 0)
        {
          closest->right = rbl;
          rbl->next = closest->right;
          rbl->prev = closest;
          closest->next = rbl;
          rbl->next->prev = rbl;
        }
      else
        return closest;		/* Ofcourse, we cannot add two identical things */
    }
  else
    tree->top = rbl;

  /* Red-black part of insert */
  
  rbl->color = RBL_RED;
  
  while(rbl->parent && rbl->parent->color == RBL_RED)
    {
      if(rbl->parent == rbl->parent->parent->left)
        {
          y = rbl->parent->parent->right;
          if(y->color == RBL_RED)
            {
              rbl->parent->color = RBL_BLACK;
              y->color = RBL_BLACK;
              rbl->parent->parent->color = RBL_RED;
              rbl = rbl->parent->parent;
            }
          else          
            {
              if(rbl == rbl->parent->right)
                {
                  rbl = rbl->parent;
                  rbl_left_rotate(rbl);
                }
              rbl->parent->color = RBL_BLACK;
              rbl->parent->parent->color = RBL_RED;
              rbl_right_rotate(rbl->parent->parent);
            }
        }
      else
        {
          y = rbl->parent->parent->left;
          if(y->color == RBL_RED)
            {
              rbl->parent->color = RBL_BLACK;
              y->color = RBL_BLACK;
              rbl->parent->parent->color = RBL_RED;
              rbl = rbl->parent->parent;
            }
          else          
            {
              if(rbl == rbl->parent->left)
                {
                  rbl = rbl->parent;
                  rbl_right_rotate(rbl);
                }
              rbl->parent->color = RBL_BLACK;
              rbl->parent->parent->color = RBL_RED;
              rbl_left_rotate(rbl->parent->parent);
            }
        }
    }
  
  tree->top->color = RBL_BLACK;

  return rbl;
}

/* Create a new node and insert it into the tree */
rbl_t rbl_insert(rbltree_t *tree, void *data)
{
  rbl_t *rbl;
  
  rbl = new_rbl();
  rbl->data = data;

  return rbl_insert_rbl(tree, rbl);
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
              x->partent->color = RBL_RED;
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
              x->partent->color = RBL_RED;
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
rbl_t rbl_unlink_rbl(rbl_t *rbl)
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
  
  if(y->color == RBL_BLACK)
    rbl_delete_fixup(x);
    
  return rbl;
}

/* Search node in tree and unlink it */
rbl_t rbl_unlink(rbltree_t *tree, void *data)
{
  rbl_t *rbl;
  
  rbl = rbl_search(tree, data);
  
  if(rbl)
    return rbl_unlink_rbl(rbl);
  else
    return NULL;
}

/* Unlink node and free it */
void rbl_delete_rbl(rbl_t *rbl)
{
  free_rbl(rbl_unlink_rbl(rbl));
}

/* Search node in tree, unlink and free it */
void rbl_delete(rbltree_t *tree, void *data)
{
  free_rbl(rbl_unlink(tree, data));
}

/* Do action for each list entry (in order)
   Deletion of entry for which action is called is allowed.
 */
void rbl_foreach(rbltree_t *tree, rbl_action_t *action)
{
  rbl_t *rbl, *next;
  
  for(rbl = tree->head; rbl; rbl = next);
    {
      next = rbl->next;
      action(rbl);
    }
}
