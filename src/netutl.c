/*
    netutl.c -- some supporting network utility code
    Copyright (C) 1998,1999,2000 Ivo Timmermans <zarq@iname.com>

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
*/

#include "config.h"

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <syslog.h>

#include <utils.h>
#include <xalloc.h>

#include "encr.h"
#include "net.h"
#include "netutl.h"

/*
  look for a connection associated with the given vpn ip,
  return its connection structure.
  Skips connections that are not activated!
*/
conn_list_t *lookup_conn(ip_t ip)
{
  conn_list_t *p = conn_list;
cp
  /* Exact match suggested by James B. MacLean */
  for(p = conn_list; p != NULL; p = p->next)
    if((ip  == p->vpn_ip) && p->active)
      return p;
  for(p = conn_list; p != NULL; p = p->next)
    if(((ip & p->vpn_mask) == (p->vpn_ip & p->vpn_mask)) && p->active)
      return p;
cp
  return NULL;
}

/*
  free a queue and all of its elements
*/
void destroy_queue(packet_queue_t *pq)
{
  queue_element_t *p, *q;
cp
  for(p = pq->head; p != NULL; p = q)
    {
      q = p->next;
      if(p->packet)
	free(p->packet);
      free(p);
    }

  free(pq);
cp
}

/*
  free a conn_list_t element and all its pointers
*/
void free_conn_element(conn_list_t *p)
{
cp
  if(p->hostname)
    free(p->hostname);
  if(p->sq)
    destroy_queue(p->sq);
  if(p->rq)
    destroy_queue(p->rq);
  free_key(p->public_key);
  free_key(p->key);
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

	  free_conn_element(p);
	}
      else
	prev = p;

      p = next;
    }
cp
}

/*
  creates new conn_list element, and initializes it
*/
conn_list_t *new_conn_list(void)
{
  conn_list_t *p = xmalloc(sizeof(*p));
cp
  /* initialise all those stupid pointers at once */
  memset(p, '\0', sizeof(*p));
  p->vpn_mask = (ip_t)(~0L); /* If this isn't done, it would be a
                                wastebucket for all packets with
                                unknown destination. */
  p->nexthop = p;
cp
  return p;
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
      free_conn_element(p);
      p = next;
    }

  conn_list = NULL;
cp
}

/*
  look up the name associated with the ip
  address `addr'
*/
char *hostlookup(unsigned long addr)
{
  char *name;
  struct hostent *host = NULL;
  struct in_addr in;
cp
  in.s_addr = addr;

  host = gethostbyaddr((char *)&in, sizeof(in), AF_INET);

  if(host)
    {
      name = xmalloc(strlen(host->h_name)+20);
      sprintf(name, "%s (%s)", host->h_name, inet_ntoa(in));
    }
  else
    {
      name = xmalloc(20);
      sprintf(name, "%s", inet_ntoa(in));
    }
cp
  return name;
}

/*
  Turn a string into an IP addy with netmask
  return NULL on failure
*/
ip_mask_t *strtoip(char *str)
{
  ip_mask_t *ip;
  int masker;
  char *q, *p;
  struct hostent *h;
cp
  p = str;
  if((q = strchr(p, '/')))
    {
      *q = '\0';
      q++; /* q now points to netmask part, or NULL if no mask */
    }

  if(!(h = gethostbyname(p)))
    {
      fprintf(stderr, "Error looking up `%s': %s\n", p, sys_errlist[h_errno]);
      return NULL;
    }

  masker = 0;
  if(q)
    {
      masker = strtol(q, &p, 10);
      if(q == p || (*p))
	return NULL;
    }

  ip = xmalloc(sizeof(*ip));
  ip->ip = ntohl(*((ip_t*)(h->h_addr_list[0])));

  ip->mask = masker ? ~((1 << (32 - masker)) - 1) : 0;
cp
  return ip;
}

void dump_conn_list(void)
{
  conn_list_t *p;
cp
  syslog(LOG_DEBUG, "Connection list:");

  for(p = conn_list; p != NULL; p = p->next)
    {
      syslog(LOG_DEBUG, " " IP_ADDR_S "/" IP_ADDR_S ": %04x (%d|%d)",
	     IP_ADDR_V(p->vpn_ip), IP_ADDR_V(p->vpn_mask), p->status,
	     p->socket, p->meta_socket);
    }
cp
}
