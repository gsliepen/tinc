/*
    list.c -- functions to deal with double linked lists
    Copyright (C) 2000,2001 Ivo Timmermans <itimmermans@bigfoot.com>
                  2000,2001 Guus Sliepen <guus@sliepen.warande.net>

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

    $Id: list.c,v 1.1.2.10 2002/03/27 15:01:16 guus Exp $
*/

#include "config.h"

#include <stdlib.h>

#include <xalloc.h>
#include <system.h>

#include "list.h"

/* (De)constructors */

list_t *list_alloc(list_action_t delete)
{
  list_t *list;

  list = xmalloc_and_zero(sizeof(list_t));
  list->delete = delete;

  return list;
}

void list_free(list_t *list)
{
  free(list);
}

list_node_t *list_alloc_node(void)
{
  list_node_t *node;
  
  node = xmalloc_and_zero(sizeof(list_node_t));
  
  return node;
}

void list_free_node(list_t *list, list_node_t *node)
{
  if(node->data && list->delete)
    list->delete(node->data);
  
  free(node);
}

/* Insertion and deletion */

list_node_t *list_insert_head(list_t *list, void *data)
{
  list_node_t *node;
  
  node = list_alloc_node();
  
  node->data = data;
  node->prev = NULL;
  node->next = list->head;
  list->head = node;
  
  if(node->next)
    node->next->prev = node;
  else
    list->tail = node;

  list->count++;

  return node;
}

list_node_t *list_insert_tail(list_t *list, void *data)
{
  list_node_t *node;
  
  node = list_alloc_node();
  
  node->data = data;
  node->next = NULL;
  node->prev = list->tail;
  list->tail = node;
  
  if(node->prev)
    node->prev->next = node;
  else
    list->head = node;

  list->count++;
  
  return node;
}

void list_unlink_node(list_t *list, list_node_t *node)
{
  if(node->prev)
    node->prev->next = node->next;
  else
    list->head = node->next;
    
  if(node->next)
    node->next->prev = node->prev;
  else
    list->tail = node->prev;

  list->count--;
}

void list_delete_node(list_t *list, list_node_t *node)
{
  list_unlink_node(list, node);
  list_free_node(list, node);
}

void list_delete_head(list_t *list)
{
  list_delete_node(list, list->head);
}

void list_delete_tail(list_t *list)
{
  list_delete_node(list, list->tail);
}

/* Head/tail lookup */

void *list_get_head(list_t *list)
{
  if(list->head)
    return list->head->data;
  else
    return NULL;
}

void *list_get_tail(list_t *list)
{
  if(list->tail)
    return list->tail->data;
  else
    return NULL;
}

/* Fast list deletion */

void list_delete_list(list_t *list)
{
  list_node_t *node, *next;
  
  for(node = list->head; node; node = next)
    {
      next = node->next;
      list_free_node(list, node);
    }

  list_free(list);
}

/* Traversing */

void list_foreach_node(list_t *list, list_action_node_t action)
{
  list_node_t *node, *next;

  for(node = list->head; node; node = next)
    {
      next = node->next;
      action(node);
    }
}

void list_foreach(list_t *list, list_action_t action)
{
  list_node_t *node, *next;

  for(node = list->head; node; node = next)
    {
      next = node->next;
      if(node->data)
        action(node->data);
    }
}
