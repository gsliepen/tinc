/*
    protocol.c -- handle the meta-protocol, basic functions
    Copyright (C) 1999-2001 Ivo Timmermans <itimmermans@bigfoot.com>,
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

    $Id: protocol.c,v 1.28.4.128 2002/03/27 15:26:43 guus Exp $
*/

#include "config.h"

#include <sys/types.h>

#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <stdio.h>
#include <stdarg.h>
#include <errno.h>

#include <utils.h>
#include <xalloc.h>

#include "conf.h"
#include "protocol.h"
#include "meta.h"
#include "connection.h"

#include "system.h"

avl_tree_t *past_request_tree;

int check_id(char *id)
{
  int i;

  for (i = 0; i < strlen(id); i++)
    if(!isalnum(id[i]) && id[i] != '_')
      return -1;
  
  return 0;
}

/* Generic request routines - takes care of logging and error
   detection as well */

int send_request(connection_t *c, const char *format, ...)
{
  va_list args;
  char buffer[MAXBUFSIZE];
  int len, request;

cp
  /* Use vsnprintf instead of vasprintf: faster, no memory
     fragmentation, cleanup is automatic, and there is a limit on the
     input buffer anyway */

  va_start(args, format);
  len = vsnprintf(buffer, MAXBUFSIZE, format, args);
  va_end(args);

  if(len < 0 || len > MAXBUFSIZE-1)
    {
      syslog(LOG_ERR, _("Output buffer overflow while sending request to %s (%s)"), c->name, c->hostname);
      return -1;
    }

  if(debug_lvl >= DEBUG_PROTOCOL)
    {
      sscanf(buffer, "%d", &request);
      if(debug_lvl >= DEBUG_META)
        syslog(LOG_DEBUG, _("Sending %s to %s (%s): %s"), request_name[request], c->name, c->hostname, buffer);
      else
        syslog(LOG_DEBUG, _("Sending %s to %s (%s)"), request_name[request], c->name, c->hostname);
    }

  buffer[len++] = '\n';
cp
  return send_meta(c, buffer, len);
}

int receive_request(connection_t *c)
{
  int request;
cp
  if(sscanf(c->buffer, "%d", &request) == 1)
    {
      if((request < 0) || (request >= LAST) || (request_handlers[request] == NULL))
        {
          if(debug_lvl >= DEBUG_META)
            syslog(LOG_DEBUG, _("Unknown request from %s (%s): %s"),
	           c->name, c->hostname, c->buffer);
          else
            syslog(LOG_ERR, _("Unknown request from %s (%s)"),
                   c->name, c->hostname);
                   
          return -1;
        }
      else
        {
          if(debug_lvl >= DEBUG_PROTOCOL)
            {
              if(debug_lvl >= DEBUG_META)
                syslog(LOG_DEBUG, _("Got %s from %s (%s): %s"),
	               request_name[request], c->name, c->hostname, c->buffer);
              else
                syslog(LOG_DEBUG, _("Got %s from %s (%s)"),
		       request_name[request], c->name, c->hostname);
            }
	}

      if((c->allow_request != ALL) && (c->allow_request != request))
        {
          syslog(LOG_ERR, _("Unauthorized request from %s (%s)"), c->name, c->hostname);
          return -1;
        }

      if(request_handlers[request](c))
	/* Something went wrong. Probably scriptkiddies. Terminate. */
        {
          syslog(LOG_ERR, _("Error while processing %s from %s (%s)"),
		 request_name[request], c->name, c->hostname);
          return -1;
        }
    }
  else
    {
      syslog(LOG_ERR, _("Bogus data received from %s (%s)"),
	     c->name, c->hostname);
      return -1;
    }
cp
  return 0;
}

int past_request_compare(past_request_t *a, past_request_t *b)
{
cp
  return strcmp(a->request, b->request);
}

void free_past_request(past_request_t *r)
{
cp
  if(r->request)
    free(r->request);
  free(r);
cp
}

void init_requests(void)
{
cp
  past_request_tree = avl_alloc_tree((avl_compare_t)past_request_compare, (avl_action_t)free_past_request);
cp
}

void exit_requests(void)
{
cp
  avl_delete_tree(past_request_tree);
cp
}

int seen_request(char *request)
{
  past_request_t p, *new;
cp
  p.request = request;

  if(avl_search(past_request_tree, &p))
    {
      if(debug_lvl >= DEBUG_SCARY_THINGS)
        syslog(LOG_DEBUG, _("Already seen request"));
      return 1;
    }
  else
    {
      new = (past_request_t *)xmalloc(sizeof(*new));
      new->request = xstrdup(request);
      new->firstseen = now;
      avl_insert(past_request_tree, new);
      return 0;
    }
cp  
}

void age_past_requests(void)
{
  avl_node_t *node, *next;
  past_request_t *p;
  int left = 0, deleted = 0;
cp 
  for(node = past_request_tree->head; node; node = next)
    {
      next = node->next;
      p = (past_request_t *)node->data;
      if(p->firstseen + pingtimeout < now)
        avl_delete_node(past_request_tree, node), deleted++;
      else
        left++;
    }

  if(debug_lvl >= DEBUG_SCARY_THINGS && left + deleted)
    syslog(LOG_DEBUG, _("Aging past requests: deleted %d, left %d\n"), deleted, left);
cp
}

/* Jumptable for the request handlers */

int (*request_handlers[])(connection_t*) = {
  id_h, metakey_h, challenge_h, chal_reply_h, ack_h,
  status_h, error_h, termreq_h,
  ping_h, pong_h,
  add_subnet_h, del_subnet_h,
  add_edge_h, del_edge_h,
  key_changed_h, req_key_h, ans_key_h,
  tcppacket_h,
};

/* Request names */

char (*request_name[]) = {
  "ID", "METAKEY", "CHALLENGE", "CHAL_REPLY", "ACK",
  "STATUS", "ERROR", "TERMREQ",
  "PING", "PONG",
  "ADD_SUBNET", "DEL_SUBNET",
  "ADD_EDGE", "DEL_EDGE",
  "KEY_CHANGED", "REQ_KEY", "ANS_KEY",
  "PACKET",
};
