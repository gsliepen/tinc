/*
    hooks.c -- hooks management
    Copyright (C) 2002 Guus Sliepen <guus@sliepen.warande.net>,
                  2002 Ivo Timmermans <ivo@o2w.nl>

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

    $Id: hooks.c,v 1.2 2002/05/02 11:50:07 zarq Exp $
*/

#include "config.h"

#include <assert.h>
#include <stdarg.h>
#include <stdio.h>

#include <avl_tree.h>
#include <hooks.h>
#include <xalloc.h>

avl_tree_t *hooks_tree = NULL;

struct hooks_node {
  const char *type;
  avl_tree_t *hooks;
} hooks_node;

static int hook_type_compare(const void *a, const void *b)
{
  return strcmp(((const struct hooks_node*)a)->type,
		((const struct hooks_node*)b)->type);
}

static int hook_dummy_compare(const void *a, const void *b)
{
  if(a < b)
    return -1;
  if(a > b)
    return 1;
  return 0;
}

void run_hooks(const char *type, ...)
{
  avl_node_t *avlnode;
  va_list args;
  struct hooks_node *hn;
  struct hooks_node target;

  if(!hooks_tree)
    return;
  
  target.type = type;
  hn = (struct hooks_node*)avl_search(hooks_tree, &target);
  if(!hn || !(hn->hooks->head))
    {
      fprintf(stderr, "Warning, no hooks found for `%s'\n", type);
      return;
    }

  va_start(args, type);
  for(avlnode = hn->hooks->head; avlnode; avlnode = avlnode->next)
    {
      assert(avlnode->data);
      ((hook_function_t*)(avlnode->data))(type, args);
    }
  va_end(args);
}

void add_hook(const char *type, hook_function_t *hook)
{
  struct hooks_node *hn;
  struct hooks_node target;
  
  if(!hooks_tree)
    hooks_tree = avl_alloc_tree(hook_type_compare, NULL);

  target.type = type;
  hn = avl_search(hooks_tree, &target);
  if(!hn)
    {
      avl_tree_t *t;
      
      hn = xmalloc(sizeof(struct hooks_node));
      t = avl_alloc_tree(hook_dummy_compare, NULL);
      hn->type = type;
      hn->hooks = t;
      avl_insert(hooks_tree, (void*)hn);
    }

  avl_insert(hn->hooks, (void*)hook);
}

void del_hook(const char *type, hook_function_t *hook)
{
  avl_tree_t *t;
  struct hooks_node target;

  if(!hooks_tree)
    return;

  target.type = type;
  t = avl_search(hooks_tree, &target);
  if(!t)
    return;

  avl_delete(t, (void*)hook);
}
