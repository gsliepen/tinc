/*
    connection.c -- connection list management
    Copyright (C) 2000-2002 Guus Sliepen <guus@sliepen.warande.net>,
                  2000-2002 Ivo Timmermans <itimmermans@bigfoot.com>

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

    $Id: connection.c,v 1.1.2.29 2002/03/22 13:31:18 guus Exp $
*/

#include "config.h"

#include <stdio.h>
#include <syslog.h>
#include <string.h>
#include <sys/time.h>

#include <avl_tree.h>
#include <list.h>

#include "net.h"	/* Don't ask. */
#include "netutl.h"
#include "config.h"
#include "conf.h"
#include <utils.h>
#include "subnet.h"

#include "xalloc.h"
#include "system.h"

avl_tree_t *connection_tree;	/* Meta connections */

int connection_compare(connection_t *a, connection_t *b)
{
  return a - b;
}

void init_connections(void)
{
cp
  connection_tree = avl_alloc_tree((avl_compare_t)connection_compare, NULL);
cp
}

void exit_connections(void)
{
cp
  avl_delete_tree(connection_tree);
cp
}

connection_t *new_connection(void)
{
  connection_t *c;
cp
  c = (connection_t *)xmalloc_and_zero(sizeof(connection_t));

  if(!c)
    return NULL;

  gettimeofday(&c->start, NULL);
cp
  return c;
}

void free_connection(connection_t *c)
{
cp
  if(c->hostname)
    free(c->hostname);
  if(c->inkey)
    free(c->inkey);
  if(c->outkey)
    free(c->outkey);
  if(c->mychallenge)
    free(c->mychallenge);
  if(c->hischallenge)
    free(c->hischallenge);
  free(c);
cp
}

void connection_add(connection_t *c)
{
cp
  avl_insert(connection_tree, c);
cp
}

void connection_del(connection_t *c)
{
cp
  avl_delete(connection_tree, c);
cp
}

void dump_connections(void)
{
  avl_node_t *node;
  connection_t *c;
cp
  syslog(LOG_DEBUG, _("Connections:"));

  for(node = connection_tree->head; node; node = node->next)
    {
      c = (connection_t *)node->data;
      syslog(LOG_DEBUG, _(" %s at %s options %lx socket %d status %04x"),
             c->name, c->hostname, c->options, c->socket, c->status);
    }
    
  syslog(LOG_DEBUG, _("End of connections."));
cp
}

int read_connection_config(connection_t *c)
{
  char *fname;
  int x;
cp
  asprintf(&fname, "%s/hosts/%s", confbase, c->name);
  x = read_config_file(c->config_tree, fname);
  free(fname);
cp
  return x;
}
