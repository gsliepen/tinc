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

    $Id: rbl.h,v 1.1.2.1 2000/11/16 09:18:38 guus Exp $
*/

typedef int (*rbl_compare_t) (const void *, const void *);
typedef void (*rbl_delete_t) (const void *);

typedef struct rbl_t
{
  /* 'red-black tree' part */

  struct rbltree_t *tree;

  int color;

  rbl_t *parent;
  rbl_t *left;
  rbl_t *right;
  
  /* 'linked list' part */
  
  rbl_t *prev;
  rbl_t *next;
  
  /* payload */
  
  void *data;
   
} rbl_t;

typedef struct rbltree_t
{
  rbl_compare_t *compare;
  rbl_delete_t *delete;
  struct rbl_t *head;
} rbltree_t;

enum
{
  RBL_RED;
  RBL_BLACK;
};

extern rbl_t rbl_search(rbltree_t *, void *);
extern rbl_t rbl_search_closest(rbltree_t *, void *);
extern rbl_t rbl_insert(rbltree_t *, void *);
extern rbl_t rbl_unlink(rbltree_t *, void *);
extern rbl_t rbl_delete(rbltree_t *, void *);
extern rbl_t rbl_insert_rbl(rbltree_t *, rbl_t *);
extern rbl_t rbl_unlink_rbl(rbltree_t *, rbl_t *);
extern rbl_t rbl_delete_rbl(rbltree_t *, rbl_t *);
extern rbl_t rbl_prev(rbl_t *);
extern rbl_t rbl_next(rbl_t *);
