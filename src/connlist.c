/*
    connlist.c -- connection list management
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

    $Id: connlist.c,v 1.1.2.5 2000/10/16 16:33:29 guus Exp $
*/

#include <syslog.h>

#include "net.h"	/* Don't ask. */
#include "config.h"
#include "conf.h"
#include <utils.h>

#include "system.h"

/* Root of the connection list */

conn_list_t *conn_list = NULL;
conn_list_t *myself = NULL;

/* Creation and deletion of conn_list elements */

conn_list_t *new_conn_list(void)
{
  conn_list_t *p = (conn_list_t *)xmalloc(sizeof(*p));
cp
  /* initialise all those stupid pointers at once */
  memset(p, '\0', sizeof(*p));
cp
  return p;
}

void free_conn_list(conn_list_t *p)
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
  if(p->public_key)
    RSA_free(p->public_key);
  if(p->cipher_pktkey)
    free(p->cipher_pktkey);
  if(p->buffer)
    free(p->buffer);
  free(p);
cp
}

/*
  remove all marked connections
*/
void prune_conn_list(void)
{
  conn_list_t *p, *prev = NULL, *next = NULL;
cp
  for(p = conn_list; p != NULL; )
    {
      next = p->next;

      if(p->status.remove)
	{
	  if(prev)
	    prev->next = next;
	  else
	    conn_list = next;

	  free_conn_list(p);
	}
      else
	prev = p;

      p = next;
    }
cp
}

/*
  free all elements of conn_list
*/
void destroy_conn_list(void)
{
  conn_list_t *p, *next;
cp
  for(p = conn_list; p != NULL; )
    {
      next = p->next;
      free_conn_list(p);
      p = next;
    }

  conn_list = NULL;
cp
}

/* Linked list management */

void conn_list_add(conn_list_t *cl)
{
cp
  cl->next = conn_list;
  cl->prev = NULL;
  if(cl->next)
    cl->next->prev = cl;
  conn_list = cl;
cp
}

void conn_list_del(conn_list_t *cl)
{
cp
  if(cl->prev)
    cl->prev->next = cl->next;
  else
    conn_list = cl->next;
  
  cl->next->prev = cl->prev;
  free_conn_list(cl);
cp
}

/* Lookup functions */

conn_list_t *lookup_id(char *name)
{
  conn_list_t *p;
cp
  for(p = conn_list; p != NULL; p = p->next)
    if(strcmp(name, p->name) == 0)
      break;
cp
  return p;
}

conn_list_t *lookup_conn_list_mac(mac_t address)
{
  conn_list_t *p;
cp
  for(p = conn_list; p != NULL; p = p->next)
    if(lookup_subnet_mac(p->subnets, address))
      break;
cp
  return p;
}

conn_list_t *lookup_conn_list_ipv4(ipv4_t address)
{
  conn_list_t *p;
cp
  for(p = conn_list; p != NULL; p = p->next)
    if(lookup_subnet_ipv4(p->subnets, address))
      break;
cp
  return p;
}

conn_list_t *lookup_conn_list_ipv6(ipv6_t address)
{
  conn_list_t *p;
cp
  for(p = conn_list; p != NULL; p = p->next)
    if(lookup_subnet_ipv6(p->subnets, address))
      break;
cp
  return p;
}

/* Debugging */

void dump_conn_list(void)
{
  conn_list_t *p;
  subnet_t *s;
  char *netstr;
cp
  syslog(LOG_DEBUG, _("Connection list:"));

  for(p = conn_list; p != NULL; p = p->next)
    {
      syslog(LOG_DEBUG, _("%s at %s port %hd flags %d sockets %d, %d status %04x"),
	     p->name, p->hostname, p->port, p->flags,
	     p->socket, p->meta_socket, p->status);
      for(s = p->subnets; s != NULL; s = s->next)
        {
          netstr = net2str(s);
          syslog(LOG_DEBUG, ": %s", netstr);
          free(netstr);
        }
    }

  syslog(LOG_DEBUG, _("End of connection list."));
cp
}

int read_host_config(conn_list_t *cl)
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
