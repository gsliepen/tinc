/*
    logging.c -- log messages to e.g. syslog
    Copyright (C) 2001-2002 Guus Sliepen <guus@sliepen.warande.net>,
                  2001-2002 Ivo Timmermans <itimmermans@bigfoot.com>

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

    $Id: logging.c,v 1.1 2002/04/28 12:46:25 zarq Exp $
*/

#include "config.h"

#include <assert.h>
#include <stdarg.h>
#include <stdio.h>
#include <syslog.h>

#include <avl_tree.h>

#include "logging.h"

avl_tree_t *log_hooks_tree = NULL;

int debug_lvl = 0;

int log_compare(const void *a, const void *b)
{
  if(a < b)
    return -1;
  if(a > b)
    return 1;
  return 0;
}

void log(int level, int priority, char *fmt, ...)
{
  avl_node_t *avlnode;
  va_list args;

  va_start(args, fmt);
  for(avlnode = log_hooks_tree->head; avlnode; avlnode = avlnode->next)
    {
      assert(avlnode->data);
      ((log_function_t*)(avlnode->data))(level, priority, fmt, args);
    }
  va_end(args);
}

void log_add_hook(log_function_t *fn)
{
  if(!log_hooks_tree)
    log_hooks_tree = avl_alloc_tree(log_compare, NULL);

  avl_insert(log_hooks_tree, (void*)fn);
}

void log_del_hook(log_function_t *fn)
{
  avl_delete(log_hooks_tree, (void*)fn);
}

void log_default(int level, int priority, char *fmt, va_list ap)
{
  if(debug_lvl >= level)
    {
      vfprintf(stderr, fmt, ap);
      fprintf(stderr, "\n");
    }
}

void log_syslog(int level, int priority, char *fmt, va_list ap)
{
  const int priorities[] = { LOG_DEBUG, LOG_INFO, LOG_NOTICE, LOG_ERR, LOG_CRIT };

  if(debug_lvl >= level)
    vsyslog(priorities[priority], fmt, ap);
}

void tinc_syslog(int priority, char *fmt, ...)
{
  /* Mapping syslog prio -> tinc prio */
  const int priorities[] = { TLOG_CRITICAL, TLOG_CRITICAL, TLOG_CRITICAL, TLOG_ERROR,
			       TLOG_NOTICE, TLOG_NOTICE, TLOG_INFO, TLOG_DEBUG };
  avl_node_t *avlnode;
  va_list args;

  va_start(args, fmt);
  for(avlnode = log_hooks_tree->head; avlnode; avlnode = avlnode->next)
    {
      assert(avlnode->data);
      ((log_function_t*)(avlnode->data))(0, priorities[priority], fmt, args);
    }
  va_end(args);
}
