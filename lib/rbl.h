/*
    rbl.h -- header file for rbl.c
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

    $Id: rbl.h,v 1.1.2.6 2000/11/19 22:12:46 guus Exp $
*/

typedef struct rbl_t
{
  /* 'red-black tree' part */

  struct rbltree_t *tree;

  int color;

  struct rbl_t *parent;
  struct rbl_t *left;
  struct rbl_t *right;
  
  /* 'linked list' part */
  
  struct rbl_t *prev;
  struct rbl_t *next;
  
  /* payload */
  
  void *data;
   
} rbl_t;

typedef int (*rbl_compare_t) (const void *, const void *);
typedef void (*rbl_action_t) (const void *);
typedef void (*rbl_action_rbl_t) (const struct rbl_t *);

typedef struct rbltree_t
{
  /* callback functions */

  rbl_compare_t compare;
  rbl_action_t delete;

  /* tree part */

  struct rbl_t *top;

  /* linked list */

  struct rbl_t *head;
  struct rbl_t *tail;

} rbltree_t;

enum color
{
  RBL_RED,
  RBL_BLACK
} color;

extern rbltree_t *new_rbltree(rbl_compare_t, rbl_action_t);
extern void free_rbltree(rbltree_t *);
extern rbl_t *new_rbl(void);
extern void free_rbl(rbl_t *);

extern void *rbl_search(rbltree_t *, void *);
extern void *rbl_search_closest(rbltree_t *, void *);
extern rbl_t *rbl_search_rbl(rbltree_t *, void *);
extern rbl_t *rbl_search_closest_rbl(rbltree_t *, void *);
extern rbl_t *rbl_insert(rbltree_t *, void *);
extern rbl_t *rbl_unlink(rbltree_t *, void *);
extern void rbl_delete(rbltree_t *, void *);
extern rbl_t *rbl_insert_rbl(rbltree_t *, rbl_t *);
extern rbl_t *rbl_unlink_rbl(rbl_t *);
extern void rbl_delete_rbl(rbl_t *);
extern void rbl_unlink_rbltree(rbltree_t *);
extern void rbl_delete_rbltree(rbltree_t *);

extern void rbl_foreach(rbltree_t *, rbl_action_t);
extern void rbl_foreach_rbl(rbltree_t *, rbl_action_rbl_t);
