/*
    connection.c -- connection list management
    Copyright (C) 2000 Guus Sliepen <guus@sliepen.warande.net>,
                  2000 Ivo Timmermans <itimmermans@bigfoot.com>

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

    $Id: connection.c,v 1.1.2.5 2000/11/22 22:18:03 guus Exp $
*/

#include "config.h"

#include <stdio.h>
#include <syslog.h>

#include <rbl.h>

#include "net.h"	/* Don't ask. */
#include "netutl.h"
#include "config.h"
#include "conf.h"
#include <utils.h>
#include "subnet.h"

#include "xalloc.h"
#include "system.h"

/* Root of the connection list */

rbltree_t *connection_tree;
rbltree_t *id_tree;

connection_t *myself = NULL;

/* Initialization and callbacks */

int connection_compare(connection_t *a, connection_t *b)
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

void init_connections(void)
{
  connection_tree = new_rbltree((rbl_compare_t)connection_compare, (rbl_action_t)free_connection);
  id_tree = new_rbltree((rbl_compare_t)id_compare, NULL);
}

/* Creation and deletion of connection elements */

connection_t *new_connection(void)
{
  connection_t *p = (connection_t *)xmalloc(sizeof(*p));
cp
  /* initialise all those stupid pointers at once */
  memset(p, '\0', sizeof(*p));

  p->subnet_tree = new_rbltree((rbl_compare_t)subnet_compare, NULL);
cp
  return p;
}

void free_connection(connection_t *p)
{
cp
  if(p->sq)
    destroy_queue(p->sq);
  if(p->rq)
    destroy_queue(p->rq);
  if(p->name && p->name!=unknown)
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
  remove all marked connections
*/
void prune_connection_tree(void)
{
  rbl_t *rbl;
  connection_t *cl;
cp
  RBL_FOREACH(connection_tree, rbl)
    {
      cl = (connection_t *) rbl->data;
      if(cl->status.remove)
        connection_del(cl);
    }
cp
}

/*
  free all elements of connection
*/
void destroy_connection_tree(void)
{
cp
  rbl_delete_rbltree(id_tree);
  rbl_delete_rbltree(connection_tree);
cp
}

/* Linked list management */

void connection_add(connection_t *cl)
{
cp
  rbl_insert(connection_tree, cl);
cp
}

void id_add(connection_t *cl)
{
cp
  rbl_insert(id_tree, cl);
cp
}

void connection_del(connection_t *cl)
{
cp
  rbl_delete(id_tree, cl);
  rbl_delete(connection_tree, cl);
cp
}

/* Lookup functions */

connection_t *lookup_connection(ipv4_t address, short unsigned int port)
{
  connection_t cl;
cp
  cl.address = address;
  cl.port = port;

  return rbl_search(connection_tree, &cl);
}

connection_t *lookup_id(char *name)
{
  connection_t cl, *p;
cp
  cl.name = name;
  p = rbl_search(id_tree, &cl);
  if(p && p->status.active)
    return p;
  else
    return NULL;
}

/* Debugging */

void dump_connection_list(void)
{
  rbl_t *rbl;
  connection_t *cl;
cp
  syslog(LOG_DEBUG, _("Connection list:"));

  syslog(LOG_DEBUG, _(" %s at %s port %hd flags %d sockets %d, %d status %04x"),
         myself->name, myself->hostname, myself->port, myself->flags,
         myself->socket, myself->meta_socket, myself->status);

  RBL_FOREACH(connection_tree, rbl)
    {
      cl = (connection_t *)rbl->data;
      syslog(LOG_DEBUG, _(" %s at %s port %hd flags %d sockets %d, %d status %04x"),
             cl->name, cl->hostname, cl->port, cl->flags,
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
