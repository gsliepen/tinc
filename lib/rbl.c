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

    $Id: rbl.c,v 1.1.2.2 2000/11/18 18:14:57 guus Exp $
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
rbltree_t *new_rbltree(rbl_compare_t *compare, rbl_delete_t *delete)
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
  
  next = rbl = tree->head;
  
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
  
  next = rbl = tree->head;
  
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
    x->tree->head = y;
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
    y->tree->head = x;
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
  
  if(tree->head)
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
    tree->head = rbl;

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
  
  tree->head->color = RBL_BLACK;

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

/* Unlink node from the tree, but keep the node intact */
rbl_t rbl_unlink_rbl(rbl_t *rbl)
{
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
