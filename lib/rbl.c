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

    $Id: rbl.c,v 1.1.2.1 2000/11/16 09:18:38 guus Exp $
*/

rbl_t *new_rbl(rbltree_t *tree)
{
  rbl_t *rbl;

  rbl = xmalloc(sizeof(*rbl));

  if(rbl)
    {
      memset(rbl, 0, sizeof(*rbl));
      rbl->tree = tree;
    }
    
  return rbl;
}

void free_rbl(rbl_t *rbl)
{
  free(rbl);
}

rbl_t rbl_search_closest(rbltree_t *tree, void *data)
{
  rbl_t *rbl, *next;
  int result;
  
  for(next = rbltree->head; next; next = rbl)
    {
      result = rbltree->compare(rbl->data, data)
      if(result < 0)
        next = rbl->left;
      else if(result > 0)
        next = rbl->right;
      else
        break;
    }
    
  return rbl;
}

rbl_t rbl_search(rbltree_t *tree, void *data)
{
  rbl_t *rbl, *next;
  int result;
  
  for(next = rbltree->head; next; next = rbl)
    {
      result = rbltree->compare(rbl->data, data)
      if(result < 0)
        next = rbl->left;
      else if(result > 0)
        next = rbl->right;
      else
        return rbl;
    }
    
  return NULL;
}

rbl_t rbl_insert(rbltree_t *tree, void *data)
{
  rbl_t *rbl;
  
}
