/*
    list.c -- functions to deal with double linked lists
    Copyright (C) 2000 Ivo Timmermans <itimmermans@bigfoot.com>
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

    $Id: list.c,v 1.1.2.6 2000/11/22 23:09:38 guus Exp $
*/

#include "config.h"

#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#include <list.h>
#include <xalloc.h>

#include <system.h>

/*
  list_new

  Initialize a new list.
*/
list_t *list_new(void)
{
  list_t *list;

  list = xmalloc_and_zero(sizeof(list_t));
  return list;
}

/*
  list_delete

  Delete the element pointed to by idx from the list.
*/
void list_delete(list_t *list, list_node_t *idx)
{
  if(!list || !idx)
    return;

  if(list->callbacks->delete != NULL)
    if(list->callbacks->delete(idx->data))
      syslog(LOG_WARNING, _("List callback[delete] failed for %08lx - freeing anyway"), idx->data);
  
  free(idx->data);
  
  if(idx->prev == NULL)
    /* First element in list */
    {
      list->head = idx->next;
    }
  if(idx->next == NULL)
    /* Last element in list */
    {
      list->tail = idx->prev;
    }
  if(idx->prev != NULL && idx->next != NULL)
    /* Neither first nor last element */
    {
      idx->prev->next = idx->next;
      idx->next->prev = idx->prev;
    }
  if(list->head == NULL)
    list->tail = NULL;
  else
    if(list->tail == NULL)
      list->head = NULL;

  free(idx);
}

/*
  list_forall_nodes

  Call function() on each element in the list.  If this function
  returns non-zero, the element will be removed from the list.
*/
void list_forall_nodes(list_t *list, int (*function)(void *data))
{
  list_node_t *p, *next;
  int res;
  
  if(!list)       /* no list given */
    return;
  if(!function)   /* no function given */
    return;
  if(!list->head) /* list is empty */
    return;
  for(p = list->head; p != NULL; p = next)
    {
      next = p->next;
      res = function(p->data);
      if(res != 0)
	list_delete(list, p);
    }
}

/*
  list_destroy

  Free all datastructures contained in this list.  It uses the delete
  callback for this list to free each element.
*/
void list_destroy(list_t *list)
{
  if(!list)
    return;
/*  list_destroy_nodes(list); */
  free(list);
}

/*
  list_append

  Append a new node to the list that points to data.
*/
void list_append(list_t *list, void *data)
{
  list_node_t *n;

  n = xmalloc_and_zero(sizeof(list_node_t));
  n->data = data;
  n->prev = list->tail;
  if(list->tail)
    list->tail->next = n;
  list->tail = n;
}
