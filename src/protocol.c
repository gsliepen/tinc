/*
    protocol.c -- handle the meta-protocol
    Copyright (C) 1999,2000 Ivo Timmermans <itimmermans@bigfoot.com>,
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

    $Id: protocol.c,v 1.28.4.14 2000/06/28 13:41:02 guus Exp $
*/

#include "config.h"

#include <sys/types.h>

#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <sys/socket.h>
#include <unistd.h>
#include <stdio.h>

#include <utils.h>
#include <xalloc.h>

#include "conf.h"
#include "encr.h"
#include "net.h"
#include "netutl.h"
#include "protocol.h"

#include "system.h"

char buffer[MAXBUFSIZE+1];
int buflen;

/* Outgoing request routines */

int send_ack(conn_list_t *cl)
{
cp
  if(debug_lvl > 1)
    syslog(LOG_DEBUG, _("Sending ACK to " IP_ADDR_S " (%s)"),
	   IP_ADDR_V(cl->vpn_ip), cl->hostname);

  buflen = snprintf(buffer, MAXBUFSIZE, "%d\n", ACK);

  if((write(cl->meta_socket, buffer, buflen)) < 0)
    {
      syslog(LOG_ERR, _("Send failed: %d:%d: %m"), __FILE__, __LINE__);
      return -1;
    }
cp
  return 0;
}

int send_termreq(conn_list_t *cl)
{
cp
  if(debug_lvl > 1)
    syslog(LOG_DEBUG, _("Sending TERMREQ to " IP_ADDR_S " (%s)"),
	   IP_ADDR_V(cl->vpn_ip), cl->hostname);

  buflen = snprintf(buffer, MAXBUFSIZE, "%d %lx\n", TERMREQ, myself->vpn_ip);

  if(write(cl->meta_socket, buffer, buflen) < 0)
    {
      if(debug_lvl > 1)
	syslog(LOG_ERR, _("Send failed: %s:%d: %m"), __FILE__, __LINE__);
      return -1;
    }
cp
  return 0;
}

int send_timeout(conn_list_t *cl)
{
cp
  if(debug_lvl > 1)
    syslog(LOG_DEBUG, _("Sending TIMEOUT to " IP_ADDR_S " (%s)"),
	   IP_ADDR_V(cl->vpn_ip), cl->hostname);

  buflen = snprintf(buffer, MAXBUFSIZE, "%d %lx\n", PINGTIMEOUT, myself->vpn_ip);

  if((write(cl->meta_socket, buffer, buflen)) < 0)
    {
      syslog(LOG_ERR, _("Send failed: %s:%d: %m"), __FILE__, __LINE__);
      return -1;
    }
cp
  return 0;
}

int send_del_host(conn_list_t *cl, conn_list_t *new_host)
{
cp
  if(debug_lvl > 1)
    syslog(LOG_DEBUG, _("Sending DEL_HOST for " IP_ADDR_S " (%s) to " IP_ADDR_S " (%s)"),
	   IP_ADDR_V(new_host->vpn_ip), new_host->hostname, IP_ADDR_V(cl->vpn_ip), cl->hostname);

  buflen = snprintf(buffer, MAXBUFSIZE, "%d %lx\n", DEL_HOST, new_host->vpn_ip);

  if((write(cl->meta_socket, buffer, buflen)) < 0)
    {
      syslog(LOG_ERR, _("Send failed: %s:%d: %m"), __FILE__, __LINE__);
      return -1;
    }
cp
  return 0;
}

int send_ping(conn_list_t *cl)
{
cp
  if(debug_lvl > 1)
    syslog(LOG_DEBUG, _("Sending PING to " IP_ADDR_S " (%s)"),
	   IP_ADDR_V(cl->vpn_ip), cl->hostname);

  buflen = snprintf(buffer, MAXBUFSIZE, "%d\n", PING);

  if((write(cl->meta_socket, buffer, buflen)) < 0)
    {
      syslog(LOG_ERR, _("Send failed: %s:%d: %m"), __FILE__, __LINE__);
      return -1;
    }
cp
  return 0;
}

int send_pong(conn_list_t *cl)
{
cp
  if(debug_lvl > 1)
    syslog(LOG_DEBUG, _("Sending PONG to " IP_ADDR_S " (%s)"),
	   IP_ADDR_V(cl->vpn_ip), cl->hostname);

  buflen = snprintf(buffer, MAXBUFSIZE, "%d\n", PONG);

  if((write(cl->meta_socket, buffer, buflen)) < 0)
    {
      syslog(LOG_ERR, _("Send failed: %s:%d: %m"), __FILE__, __LINE__);
      return -1;
    }
cp
  return 0;
}

int send_add_host(conn_list_t *cl, conn_list_t *new_host)
{
  ip_t real_ip;
  int flags;
  char *hostname;
cp
  real_ip = new_host->real_ip;
  hostname = new_host->hostname;
  flags = new_host->flags;
  
  /* If we need to propagate information about a new host that wants us to export
   * it's indirectdata flag, we set the INDIRECTDATA flag and unset the EXPORT...
   * flag, and set it's real_ip to our vpn_ip, so that net.c send_packet() will
   * work correctly.
   */
     
  if(flags & EXPORTINDIRECTDATA)
    {
      flags &= ~EXPORTINDIRECTDATA;
      flags |= INDIRECTDATA;
      real_ip = myself->vpn_ip;
      hostname = myself->hostname;
    }

  if(debug_lvl > 1)
    syslog(LOG_DEBUG, _("Sending ADD_HOST for " IP_ADDR_S " (%s) to " IP_ADDR_S " (%s)"),
	   IP_ADDR_V(new_host->vpn_ip), hostname, IP_ADDR_V(cl->vpn_ip), cl->hostname);

  buflen = snprintf(buffer, MAXBUFSIZE, "%d %lx %lx/%lx:%x %d\n", ADD_HOST, real_ip, new_host->vpn_ip, new_host->vpn_mask, new_host->port, flags);

  if((write(cl->meta_socket, buffer, buflen)) < 0)
    {
      syslog(LOG_ERR, _("Send failed: %s:%d: %m"), __FILE__, __LINE__);
      return -1;
    }
cp
  return 0;
}

int send_key_changed(conn_list_t *cl, conn_list_t *src)
{
cp
  if(debug_lvl > 1)
    syslog(LOG_DEBUG, _("Sending KEY_CHANGED origin " IP_ADDR_S " to " IP_ADDR_S " (%s)"),
	   IP_ADDR_V(src->vpn_ip), IP_ADDR_V(cl->vpn_ip), cl->hostname);

  buflen = snprintf(buffer, MAXBUFSIZE, "%d %lx\n", KEY_CHANGED, src->vpn_ip);

  if((write(cl->meta_socket, buffer, buflen)) < 0)
    {
      syslog(LOG_ERR, _("Send failed: %s:%d: %m"), __FILE__, __LINE__);
      return -1;
    }
cp
  return 0;
}

void send_key_changed_all(void)
{
  conn_list_t *p;
cp
  for(p = conn_list; p != NULL; p = p->next)
    if(p->status.meta && p->status.active)
      send_key_changed(p, myself);
cp
}

int send_basic_info(conn_list_t *cl)
{
cp
  if(debug_lvl > 1)
    syslog(LOG_DEBUG, _("Sending BASIC_INFO to %s"),
	   cl->hostname);

  buflen = snprintf(buffer, MAXBUFSIZE, "%d %d %lx/%lx:%x %d\n", BASIC_INFO, PROT_CURRENT, myself->vpn_ip, myself->vpn_mask, myself->port, myself->flags);

  if((write(cl->meta_socket, buffer, buflen)) < 0)
    {
      syslog(LOG_ERR, _("Send failed: %s:%d: %m"), __FILE__, __LINE__);
      return -1;
    }
cp
  return 0;
}

int send_passphrase(conn_list_t *cl)
{
  passphrase_t tmp;
cp
  encrypt_passphrase(&tmp);

  if(debug_lvl > 1)
    syslog(LOG_DEBUG, _("Sending PASSPHRASE to " IP_ADDR_S " (%s)"),
	   IP_ADDR_V(cl->vpn_ip), cl->hostname);

  buflen = snprintf(buffer, MAXBUFSIZE, "%d %s\n", PASSPHRASE, tmp.phrase);

  if((write(cl->meta_socket, buffer, buflen)) < 0)
    {
      syslog(LOG_ERR, _("Send failed: %s:%d: %m"), __FILE__, __LINE__);
      return -1;
    }
cp
  return 0;
}

int send_public_key(conn_list_t *cl)
{
cp
  if(debug_lvl > 1)
    syslog(LOG_DEBUG, _("Sending PUBLIC_KEY to " IP_ADDR_S " (%s)"),
	   IP_ADDR_V(cl->vpn_ip), cl->hostname);

  buflen = snprintf(buffer, MAXBUFSIZE, "%d %s\n", PUBLIC_KEY, my_public_key_base36);

  if((write(cl->meta_socket, buffer, buflen)) < 0)
    {
      syslog(LOG_ERR, _("Send failed: %s:%d: %m"), __FILE__, __LINE__);
      return -1;
    }
cp
  return 0;
}

/* WDN doet deze functie? (GS)
int send_calculate(conn_list_t *cl, char *k)
{
cp
  buflen = snprintf(buffer, MAXBUFSIZE, "%d %s\n", CALCULATE, k);

  if((write(cl->meta_socket, buffer, buflen)) < 0)
    {
      syslog(LOG_ERR, _("Send failed: %s:%d: %m"), __FILE__, __LINE__);
      return -1;
    }
cp
  return 0;
}
*/

int send_key_request(ip_t to)
{
  conn_list_t *fw;
cp
  fw = lookup_conn(to);
  if(!fw)
    {
      syslog(LOG_ERR, _("Attempting to send REQ_KEY to " IP_ADDR_S ", which does not exist?"),
	     IP_ADDR_V(to));
      return -1;
    }

  if(debug_lvl > 1)
    syslog(LOG_DEBUG, _("Sending REQ_KEY to " IP_ADDR_S " (%s)"),
	   IP_ADDR_V(fw->nexthop->vpn_ip), fw->nexthop->hostname);

  buflen = snprintf(buffer, MAXBUFSIZE, "%d %lx %lx\n", REQ_KEY, to, myself->vpn_ip);

  if((write(fw->nexthop->meta_socket, buffer, buflen)) < 0)
    {
      syslog(LOG_ERR, _("Send failed: %s:%d: %m"), __FILE__, __LINE__);
      return -1;
    }
  fw->status.waitingforkey = 1;
cp
  return 0;
}

int send_key_answer(conn_list_t *cl, ip_t to)
{
  conn_list_t *fw;
cp

  fw = lookup_conn(to);
  
  if(!fw)
    {
      syslog(LOG_ERR, _("Attempting to send ANS_KEY to " IP_ADDR_S ", which does not exist?"),
	     IP_ADDR_V(to));
      return -1;
    }

 if(debug_lvl > 1)
    syslog(LOG_DEBUG, _("Sending ANS_KEY to " IP_ADDR_S " (%s)"),
	   IP_ADDR_V(fw->nexthop->vpn_ip), fw->nexthop->hostname);

  buflen = snprintf(buffer, MAXBUFSIZE, "%d %lx %lx %d %s\n", ANS_KEY, to, myself->vpn_ip, my_key_expiry, my_public_key_base36);

  if((write(fw->nexthop->meta_socket, buffer, buflen)) < 0)
    {
      syslog(LOG_ERR, _("Send failed: %s:%d: %m"), __FILE__, __LINE__);
      return -1;
    }
cp
  return 0;
}

/*
  notify all my direct connections of a new host
  that was added to the vpn, with the exception
  of the source of the announcement.
*/
int notify_others(conn_list_t *new, conn_list_t *source,
		  int (*function)(conn_list_t*, conn_list_t*))
{
  conn_list_t *p;
cp
  for(p = conn_list; p != NULL; p = p->next)
    if(p != new && p != source && p->status.meta && p->status.active)
      function(p, new);
cp
  return 0;
}

/*
  notify one connection of everything
  i have connected
*/
int notify_one(conn_list_t *new)
{
  conn_list_t *p;
cp
  for(p = conn_list; p != NULL; p = p->next)
    if(p != new && p->status.active)
      send_add_host(new, p);
cp
  return 0;
}

/*
  The incoming request handlers
*/

int basic_info_h(conn_list_t *cl)
{
cp
  if(debug_lvl > 1)
    syslog(LOG_DEBUG, _("Got BASIC_INFO from %s"), cl->hostname);

  if(sscanf(cl->buffer, "%*d %d %lx/%lx:%hx %d", &cl->protocol_version, &cl->vpn_ip, &cl->vpn_mask, &cl->port, &cl->flags) != 5)
    {
       syslog(LOG_ERR, _("Got bad BASIC_INFO from %s"),
              cl->hostname);
       return -1;
    }  

  if(cl->protocol_version != PROT_CURRENT)
    {
      syslog(LOG_ERR, _("Peer uses incompatible protocol version %d"),
	     cl->protocol_version);
      return -1;
    }

  if(cl->status.outgoing)
    {
      if(setup_vpn_connection(cl) < 0)
	return -1;
      send_basic_info(cl);
    }
  else
    {
      if(setup_vpn_connection(cl) < 0)
	return -1;
      send_passphrase(cl);
    }
cp
  return 0;
}

int passphrase_h(conn_list_t *cl)
{
cp
  cl->pp = xmalloc(sizeof(*(cl->pp)));

  if(sscanf(cl->buffer, "%*d %as", &(cl->pp->phrase)) != 1)
    {
      syslog(LOG_ERR, _("Got bad PASSPHRASE from " IP_ADDR_S " (%s)"),
              IP_ADDR_V(cl->vpn_ip), cl->hostname);
      return -1;
    }
  cl->pp->len = strlen(cl->pp->phrase);
    
  if(debug_lvl > 1)
    syslog(LOG_DEBUG, _("Got PASSPHRASE from " IP_ADDR_S " (%s)"),
              IP_ADDR_V(cl->vpn_ip), cl->hostname);

  if(cl->status.outgoing)
    send_passphrase(cl);
  else
    send_public_key(cl);
cp
  return 0;
}

int public_key_h(conn_list_t *cl)
{
  char *g_n;
  conn_list_t *old;
cp
  if(sscanf(cl->buffer, "%*d %as", &g_n) != 1)
    {
       syslog(LOG_ERR, _("Got bad PUBLIC_KEY from " IP_ADDR_S " (%s)"),
              IP_ADDR_V(cl->vpn_ip), cl->hostname);
       return -1;
    }  

  if(debug_lvl > 1)
    syslog(LOG_DEBUG, _("Got PUBLIC_KEY from " IP_ADDR_S " (%s)"),
              IP_ADDR_V(cl->vpn_ip), cl->hostname);

  if(verify_passphrase(cl, g_n))
    {
      /* intruder! */
      syslog(LOG_ERR, _("Intruder: passphrase does not match!"));
      return -1;
    }

  if(cl->status.outgoing)
    send_public_key(cl);
  else
    {
      send_ack(cl);

      /* Okay, before we active the connection, we check if there is another entry
         in the connection list with the same vpn_ip. If so, it presumably is an
         old connection that has timed out but we don't know it yet. Because our
         conn_list entry is not active, lookup_conn will skip ourself. */

      while(old = lookup_conn(cl->vpn_ip)) 
        terminate_connection(old);

      cl->status.active = 1;

      if(debug_lvl > 0)
        syslog(LOG_NOTICE, _("Connection with " IP_ADDR_S " (%s) activated"),
                           IP_ADDR_V(cl->vpn_ip), cl->hostname);

      notify_others(cl, NULL, send_add_host);
      notify_one(cl);
    }
cp
  return 0;
}

int ack_h(conn_list_t *cl)
{
cp
  if(debug_lvl > 1)
    syslog(LOG_DEBUG, _("Got ACK from " IP_ADDR_S " (%s)"),
              IP_ADDR_V(cl->vpn_ip), cl->hostname);
  
  cl->status.active = 1;

  syslog(LOG_NOTICE, _("Connection with " IP_ADDR_S " (%s) activated"),
              IP_ADDR_V(cl->vpn_ip), cl->hostname);

  notify_others(cl, NULL, send_add_host);
  notify_one(cl);

  upstreamindex = 0;
cp
  return 0;
}

int termreq_h(conn_list_t *cl)
{
cp
  if(!cl->status.active)
    {
      syslog(LOG_ERR, _("Got unauthorized TERMREQ from " IP_ADDR_S " (%s)"),
              IP_ADDR_V(cl->vpn_ip), cl->hostname);
      return -1;
    }
    
  if(debug_lvl > 1)
   syslog(LOG_DEBUG, _("Got TERMREQ from " IP_ADDR_S " (%s)"),
             IP_ADDR_V(cl->vpn_ip), cl->hostname);
  
  cl->status.termreq = 1;

  if(cl->status.active)
    notify_others(cl, NULL, send_del_host);

  cl->status.active = 0;

  terminate_connection(cl);
cp
  return 0;
}

int timeout_h(conn_list_t *cl)
{
cp
  if(!cl->status.active)
    {
      syslog(LOG_ERR, _("Got unauthorized TIMEOUT from " IP_ADDR_S " (%s)"),
              IP_ADDR_V(cl->vpn_ip), cl->hostname);
      return -1;
    }

  if(debug_lvl > 1)
    syslog(LOG_DEBUG, _("Got TIMEOUT from " IP_ADDR_S " (%s)"),
              IP_ADDR_V(cl->vpn_ip), cl->hostname);

  cl->status.termreq = 1;
  terminate_connection(cl);
cp
  return 0;
}

int del_host_h(conn_list_t *cl)
{
  ip_t vpn_ip;
  conn_list_t *fw;
cp
  if(!cl->status.active)
    {
      syslog(LOG_ERR, _("Got unauthorized DEL_HOST from " IP_ADDR_S " (%s)"),
              IP_ADDR_V(cl->vpn_ip), cl->hostname);
      return -1;
    }

  if(sscanf(cl->buffer, "%*d %lx", &vpn_ip) != 1)
    {
       syslog(LOG_ERR, _("Got bad DEL_HOST from " IP_ADDR_S " (%s)"),
              IP_ADDR_V(cl->vpn_ip), cl->hostname);
       return -1;
    }  

  if(!(fw = lookup_conn(vpn_ip)))
    {
      syslog(LOG_ERR, _("Got DEL_HOST for " IP_ADDR_S " from " IP_ADDR_S " (%s) which does not exist?"),
	     IP_ADDR_V(vpn_ip), IP_ADDR_V(cl->vpn_ip), cl->hostname);
      return 0;
    }

  if(debug_lvl > 1)
    syslog(LOG_DEBUG, _("Got DEL_HOST for " IP_ADDR_S " (%s) from " IP_ADDR_S " (%s)"),
           IP_ADDR_V(fw->vpn_ip), fw->hostname, IP_ADDR_V(cl->vpn_ip), cl->hostname);

  notify_others(fw, cl, send_del_host);

  fw->status.termreq = 1;
  fw->status.active = 0;

  terminate_connection(fw);
cp
  return 0;
}

int ping_h(conn_list_t *cl)
{
cp
  if(!cl->status.active)
    {
      syslog(LOG_ERR, _("Got unauthorized PING from " IP_ADDR_S " (%s)"),
              IP_ADDR_V(cl->vpn_ip), cl->hostname);
      return -1;
    }

  if(debug_lvl > 1)
    syslog(LOG_DEBUG, _("Got PING from " IP_ADDR_S " (%s)"),
              IP_ADDR_V(cl->vpn_ip), cl->hostname);

  cl->status.pinged = 0;
  cl->status.got_pong = 1;

  send_pong(cl);
cp
  return 0;
}

int pong_h(conn_list_t *cl)
{
cp
  if(!cl->status.active)
    {
      syslog(LOG_ERR, _("Got unauthorized PONG from " IP_ADDR_S " (%s)"),
              IP_ADDR_V(cl->vpn_ip), cl->hostname);
      return -1;
    }

  if(debug_lvl > 1)
    syslog(LOG_DEBUG, _("Got PONG from " IP_ADDR_S " (%s)"),
              IP_ADDR_V(cl->vpn_ip), cl->hostname);

  cl->status.got_pong = 1;
cp
  return 0;
}

int add_host_h(conn_list_t *cl)
{
  ip_t real_ip;
  ip_t vpn_ip;
  ip_t vpn_mask;
  unsigned short port;
  int flags;
  conn_list_t *ncn, *old;
cp
  if(!cl->status.active)
    {
      syslog(LOG_ERR, _("Got unauthorized ADD_HOST from " IP_ADDR_S " (%s)"),
              IP_ADDR_V(cl->vpn_ip), cl->hostname);
      return -1;
    }
    
  if(sscanf(cl->buffer, "%*d %lx %lx/%lx:%hx %d", &real_ip, &vpn_ip, &vpn_mask, &port, &flags) != 5)
    {
       syslog(LOG_ERR, _("Got bad ADD_HOST from " IP_ADDR_S " (%s)"),
              IP_ADDR_V(cl->vpn_ip), cl->hostname);
       return -1;
    }  

  while(old = lookup_conn(vpn_ip))
      terminate_connection(old);
    
  ncn = new_conn_list();
  ncn->real_ip = real_ip;
  ncn->hostname = hostlookup(htonl(real_ip));
  ncn->vpn_ip = vpn_ip;
  ncn->vpn_mask = vpn_mask;
  ncn->port = port;
  ncn->flags = flags;
  ncn->nexthop = cl;
  ncn->next = conn_list;
  conn_list = ncn;
  ncn->status.active = 1;

  if(debug_lvl > 1)
    syslog(LOG_DEBUG, _("Got ADD_HOST for " IP_ADDR_S " (%s) from " IP_ADDR_S " (%s)"),
           IP_ADDR_V(ncn->vpn_ip), ncn->hostname, IP_ADDR_V(cl->vpn_ip), cl->hostname);

  notify_others(ncn, cl, send_add_host);
cp
  return 0;
}

int req_key_h(conn_list_t *cl)
{
  ip_t to;
  ip_t from;
  conn_list_t *fw;
cp
  if(!cl->status.active)
    {
      syslog(LOG_ERR, _("Got unauthorized REQ_KEY from " IP_ADDR_S " (%s)"),
              IP_ADDR_V(cl->vpn_ip), cl->hostname);
      return -1;
    }

  if(sscanf(cl->buffer, "%*d %lx %lx", &to, &from) != 2)
    {
       syslog(LOG_ERR, _("Got bad REQ_KEY from " IP_ADDR_S " (%s)"),
              IP_ADDR_V(cl->vpn_ip), cl->hostname);
       return -1;
    }  

  if(debug_lvl > 1)
    syslog(LOG_DEBUG, _("Got REQ_KEY origin " IP_ADDR_S " destination " IP_ADDR_S " from " IP_ADDR_S " (%s)"),
           IP_ADDR_V(from), IP_ADDR_V(to), IP_ADDR_V(cl->vpn_ip), cl->hostname);

  if((to & myself->vpn_mask) == (myself->vpn_ip & myself->vpn_mask))
    {  /* hey! they want something from ME! :) */
      send_key_answer(cl, from);
      return 0;
    }

  fw = lookup_conn(to);
  
  if(!fw)
    {
      syslog(LOG_ERR, _("Attempting to forward REQ_KEY to " IP_ADDR_S ", which does not exist?"),
	     IP_ADDR_V(to));
      return -1;
    }

  if(debug_lvl > 1)
    syslog(LOG_DEBUG, _("Forwarding REQ_KEY to " IP_ADDR_S " (%s)"),
	   IP_ADDR_V(fw->nexthop->vpn_ip), fw->nexthop->hostname);
  
  cl->buffer[cl->reqlen-1] = '\n';
  
  if(write(fw->nexthop->meta_socket, cl->buffer, cl->reqlen) < 0)
    {
      syslog(LOG_ERR, _("Send failed: %s:%d: %m"), __FILE__, __LINE__);
      return -1;
    }
cp
  return 0;
}

void set_keys(conn_list_t *cl, int expiry, char *key)
{
  char *ek;
cp
  if(!cl->public_key)
    {
      cl->public_key = xmalloc(sizeof(*cl->key));
      cl->public_key->key = NULL;
    }
    
  if(cl->public_key->key)
    free(cl->public_key->key);
  cl->public_key->length = strlen(key);
  cl->public_key->expiry = expiry;
  cl->public_key->key = xmalloc(cl->public_key->length + 1);
  strcpy(cl->public_key->key, key);

  ek = make_shared_key(key);
  
  if(!cl->key)
    {
      cl->key = xmalloc(sizeof(*cl->key));
      cl->key->key = NULL;
    }

  if(cl->key->key)
    free(cl->key->key);

  cl->key->length = strlen(ek);
  cl->key->expiry = expiry;
  cl->key->key = xmalloc(cl->key->length + 1);
  strcpy(cl->key->key, ek);
cp
}

int ans_key_h(conn_list_t *cl)
{
  ip_t to;
  ip_t from;
  int expiry;
  char *key;
  conn_list_t *fw, *gk;
cp
  if(!cl->status.active)
    {
      syslog(LOG_ERR, _("Got unauthorized ANS_KEY from " IP_ADDR_S " (%s)"),
              IP_ADDR_V(cl->vpn_ip), cl->hostname);
      return -1;
    }

  if(sscanf(cl->buffer, "%*d %lx %lx %d %as", &to, &from, &expiry, &key) != 4)
    {
       syslog(LOG_ERR, _("Got bad ANS_KEY from " IP_ADDR_S " (%s)"),
              IP_ADDR_V(cl->vpn_ip), cl->hostname);
       return -1;
    }  

  if(debug_lvl > 1)
    syslog(LOG_DEBUG, _("Got ANS_KEY origin " IP_ADDR_S " destination " IP_ADDR_S " from " IP_ADDR_S " (%s)"),
            IP_ADDR_V(from), IP_ADDR_V(to), IP_ADDR_V(cl->vpn_ip), cl->hostname);

  if(to == myself->vpn_ip)
    {  /* hey! that key's for ME! :) */
      gk = lookup_conn(from);

      if(!gk)
        {
          syslog(LOG_ERR, _("Receiving ANS_KEY from " IP_ADDR_S ", which does not exist?"),
	         IP_ADDR_V(from));
          return -1;
        }

      set_keys(gk, expiry, key);
      gk->status.validkey = 1;
      gk->status.waitingforkey = 0;
      flush_queues(gk);
      return 0;
    }

  fw = lookup_conn(to);
  
  if(!fw)
    {
      syslog(LOG_ERR, _("Attempting to forward ANS_KEY to " IP_ADDR_S ", which does not exist?"),
	     IP_ADDR_V(to));
      return -1;
    }

  if(debug_lvl > 1)
    syslog(LOG_DEBUG, _("Forwarding ANS_KEY to " IP_ADDR_S " (%s)"),
	   IP_ADDR_V(fw->nexthop->vpn_ip), fw->nexthop->hostname);

  cl->buffer[cl->reqlen-1] = '\n';

  if((write(fw->nexthop->meta_socket, cl->buffer, cl->reqlen)) < 0)
    {
      syslog(LOG_ERR, _("Send failed: %s:%d: %m"), __FILE__, __LINE__);
      return -1;
    }
cp
  return 0;
}

int key_changed_h(conn_list_t *cl)
{
  ip_t from;
  conn_list_t *ik;
cp
  if(!cl->status.active)
    {
      syslog(LOG_ERR, _("Got unauthorized KEY_CHANGED from " IP_ADDR_S " (%s)"),
              IP_ADDR_V(cl->vpn_ip), cl->hostname);
      return -1;
    }

  if(sscanf(cl->buffer, "%*d %lx", &from) != 1)
    {
       syslog(LOG_ERR, _("Got bad KEY_CHANGED from " IP_ADDR_S " (%s)"),
              IP_ADDR_V(cl->vpn_ip), cl->hostname);
       return -1;
    }  

  if(debug_lvl > 1)
    syslog(LOG_DEBUG, _("Got KEY_CHANGED origin " IP_ADDR_S " from " IP_ADDR_S " (%s)"),
            IP_ADDR_V(from), IP_ADDR_V(cl->vpn_ip), cl->hostname);

  ik = lookup_conn(from);

  if(!ik)
    {
      syslog(LOG_ERR, _("Got KEY_CHANGED from " IP_ADDR_S ", which does not exist?"),
	     IP_ADDR_V(from));
      return -1;
    }

  ik->status.validkey = 0;
  ik->status.waitingforkey = 0;

  notify_others(ik, cl, send_key_changed);
cp
  return 0;
}

int (*request_handlers[256])(conn_list_t*) = {
  0, ack_h, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  termreq_h, timeout_h, del_host_h, 0, 0, 0, 0, 0, 0, 0,
  ping_h, pong_h, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  add_host_h, basic_info_h, passphrase_h, public_key_h, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  req_key_h, ans_key_h, key_changed_h, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  0, 0, 0, 0, 0, 0
};
