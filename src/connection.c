/*
    connection.c -- connection list management
    Copyright (C) 2000,2001 Guus Sliepen <guus@sliepen.warande.net>,
                  2000,2001 Ivo Timmermans <itimmermans@bigfoot.com>

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

    $Id: connection.c,v 1.1.2.15 2001/07/21 15:34:18 guus Exp $
*/

#include "config.h"

#include <stdio.h>
#include <syslog.h>
#include <string.h>

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

/* Root of the connection list */

avl_tree_t *connection_tree;	/* Meta connections */
avl_tree_t *active_tree;	/* Activated hosts, sorted by address and port */
avl_tree_t *id_tree;		/* Activated hosts, sorted by name */
avl_tree_t *prune_tree;		/* connection_t structures which have to be freed */

/* Pointer to connection describing myself */

connection_t *myself = NULL;

/* Initialization and callbacks */

int connection_compare(connection_t *a, connection_t *b)
{
  return a->meta_socket - b->meta_socket;
}

int active_compare(connection_t *a, connection_t *b)
{
  ipv4_t result;

  result = a->address - b->address;
  if(result)
    return result;
  else
    return a->port - b->port;
}

int id_compare(connection_t *a, connection_t *b)
{
  return strcmp(a->name, b->name);
}

int prune_compare(connection_t *a, connection_t *b)
{
  if(a < b)
    return -1;
  else if(a > b)
    return 1;
  else
    return 0;
}

void init_connections(void)
{
  connection_tree = avl_alloc_tree((avl_compare_t)connection_compare, NULL);
  active_tree = avl_alloc_tree((avl_compare_t)active_compare, NULL);
  id_tree = avl_alloc_tree((avl_compare_t)id_compare, NULL);
  prune_tree = avl_alloc_tree((avl_compare_t)prune_compare, (avl_action_t)free_connection);
}

/* Creation and deletion of connection elements */

connection_t *new_connection(void)
{
  connection_t *p = (connection_t *)xmalloc_and_zero(sizeof(*p));
cp
  p->subnet_tree = avl_alloc_tree((avl_compare_t)subnet_compare, NULL);
  p->queue = list_alloc((list_action_t)free);
cp
  return p;
}

void free_connection(connection_t *p)
{
cp
  if(p->queue)
    list_delete_list(p->queue);
  if(p->name)
    free(p->name);
  if(p->hostname)
    free(p->hostname);
  if(p->rsa_key)
    RSA_free(p->rsa_key);
  if(p->cipher_pktkey)
    free(p->cipher_pktkey);
  if(p->buffer)
    free(p->buffer);
  if(p->config)
    clear_config(&p->config);
  free(p);
cp
}

/*
  Free all trees.
*/
void destroy_trees(void)
{
cp
  avl_delete_tree(id_tree);
  avl_delete_tree(active_tree);
  avl_delete_tree(connection_tree);
  avl_delete_tree(prune_tree);
cp
}

/* Connection management */

void connection_add(connection_t *cl)
{
cp
  avl_insert(connection_tree, cl);
cp
}

void connection_del(connection_t *cl)
{
cp
  active_del(cl);

  if(cl->status.meta)
    avl_delete(connection_tree, cl);
cp
}

void active_add(connection_t *cl)
{
cp
  avl_insert(active_tree, cl);
  avl_insert(id_tree, cl);
  cl->status.active = 1;
cp
}

void active_del(connection_t *cl)
{
cp
  if(cl->status.active)
  {
    avl_delete(id_tree, cl);
    avl_delete(active_tree, cl);
  }
cp
}

void id_add(connection_t *cl)
{
cp
  avl_insert(id_tree, cl);
cp
}

void prune_add(connection_t *cl)
{
cp
  avl_insert(prune_tree, cl);
cp
}

void prune_flush(void)
{
  avl_node_t *node, *next;
cp
  for(node = prune_tree->head; node; node = next)
    {
      next = node->next;
      avl_delete_node(prune_tree, node);
    }
cp
}

/* Lookup functions */

connection_t *lookup_active(ipv4_t address, short unsigned int port)
{
  connection_t cl;
cp
  cl.address = address;
  cl.port = port;

  return avl_search(active_tree, &cl);
}

connection_t *lookup_id(char *name)
{
  connection_t cl, *p;
cp
  cl.name = name;
  p = avl_search(id_tree, &cl);
  if(p)
    return p;
  else
    return NULL;
}

/* Debugging */

void dump_connection_list(void)
{
  avl_node_t *node;
  connection_t *cl;
cp
  syslog(LOG_DEBUG, _("Connection list:"));

  for(node = connection_tree->head; node; node = node->next)
    {
      cl = (connection_t *)node->data;
      syslog(LOG_DEBUG, _(" %s at %s port %hd options %ld sockets %d, %d status %04x"),
             cl->name, cl->hostname, cl->port, cl->options,
             cl->socket, cl->meta_socket, cl->status);
    }
    
  syslog(LOG_DEBUG, _("Known hosts:"));

  for(node = id_tree->head; node; node = node->next)
    {
      cl = (connection_t *)node->data;
      syslog(LOG_DEBUG, _(" %s at %s port %hd options %ld sockets %d, %d status %04x"),
             cl->name, cl->hostname, cl->port, cl->options,
             cl->socket, cl->meta_socket, cl->status);
    }
    
  syslog(LOG_DEBUG, _("End of connection list."));
cp
}

int read_host_config(connection_t *cl)
{
  char *fname;
  int x;
cp
  asprintf(&fname, "%s/hosts/%s", confbase, cl->name);
  x = read_config_file(&cl->config, fname);
  free(fname);
cp
  return x;
}
