/*
    protocol.c -- handle the meta-protocol
    Copyright (C) 1999 Ivo Timmermans <zarq@iname.com>

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

char buffer[MAXBUFSIZE];
int buflen;

int send_ack(conn_list_t *cl)
{
cp
  if(debug_lvl > 2)
    syslog(LOG_DEBUG, "Send ACK to %s", cl->hostname);

  buflen = sprintf(buffer, "%d\n", ACK);

  if((write(cl->meta_socket, buffer, buflen)) < 0)
    {
      syslog(LOG_ERR, "send failed: %d:%d: %m", __FILE__, __LINE__);
      return -1;
    }

  syslog(LOG_NOTICE, "Connection with %s activated.", cl->hostname);
cp
  return 0;
}

int send_termreq(conn_list_t *cl)
{
cp
  if(debug_lvl > 2)
    syslog(LOG_DEBUG, "Send TERMREQ to " IP_ADDR_S,
	   IP_ADDR_V(cl->vpn_ip));

  buflen = sprintf(buffer, "%d %lx\n", TERMREQ, myself->vpn_ip);

  if((write(cl->meta_socket, buffer, buflen)) < 0)
    {
      syslog(LOG_ERR, "send failed: %s:%d: %m", __FILE__, __LINE__);
      return -1;
    }
cp
  return 0;
}

int send_timeout(conn_list_t *cl)
{
cp
  if(debug_lvl > 2)
    syslog(LOG_DEBUG, "Send TIMEOUT to " IP_ADDR_S,
	   IP_ADDR_V(cl->vpn_ip));

  buflen = sprintf(buffer, "%d %lx\n", PINGTIMEOUT, myself->vpn_ip);

  if((write(cl->meta_socket, buffer, buflen)) < 0)
    {
      syslog(LOG_ERR, "send failed: %s:%d: %m", __FILE__, __LINE__);
      return -1;
    }
cp
  return 0;
}

int send_del_host(conn_list_t *cl, conn_list_t *new_host)
{
cp
  if(debug_lvl > 2)
    syslog(LOG_DEBUG, "Sending delete host " IP_ADDR_S " to " IP_ADDR_S,
	   IP_ADDR_V(new_host->vpn_ip), IP_ADDR_V(cl->vpn_ip));

  buflen = sprintf(buffer, "%d %lx\n", DEL_HOST, new_host->vpn_ip);

  if((write(cl->meta_socket, buffer, buflen)) < 0)
    {
      syslog(LOG_ERR, "send failed: %s:%d: %m", __FILE__, __LINE__);
      return -1;
    }
cp
  return 0;
}

int send_ping(conn_list_t *cl)
{
cp
  if(debug_lvl > 3)
    syslog(LOG_DEBUG, "pinging " IP_ADDR_S, IP_ADDR_V(cl->vpn_ip));

  buflen = sprintf(buffer, "%d\n", PING);

  if((write(cl->meta_socket, buffer, buflen)) < 0)
    {
      syslog(LOG_ERR, "send failed: %s:%d: %m", __FILE__, __LINE__);
      return -1;
    }
cp
  return 0;
}

int send_pong(conn_list_t *cl)
{
cp
  buflen = sprintf(buffer, "%d\n", PONG);

  if((write(cl->meta_socket, buffer, buflen)) < 0)
    {
      syslog(LOG_ERR, "send failed: %s:%d: %m", __FILE__, __LINE__);
      return -1;
    }
cp
  return 0;
}

int send_add_host(conn_list_t *cl, conn_list_t *new_host)
{
cp
  if(debug_lvl > 2)
    syslog(LOG_DEBUG, "Sending add host to " IP_ADDR_S,
	   IP_ADDR_V(cl->vpn_ip));

  buflen = sprintf(buffer, "%d %lx %lx/%lx:%x\n", ADD_HOST, new_host->real_ip, new_host->vpn_ip, new_host->vpn_mask, new_host->port);

  if((write(cl->meta_socket, buffer, buflen)) < 0)
    {
      syslog(LOG_ERR, "send failed: %s:%d: %m", __FILE__, __LINE__);
      return -1;
    }
cp
  return 0;
}

int send_key_changed(conn_list_t *cl, conn_list_t *src)
{
cp
  if(debug_lvl > 2)
    syslog(LOG_DEBUG, "Sending KEY_CHANGED to " IP_ADDR_S,
	   IP_ADDR_V(cl->vpn_ip));

  buflen = sprintf(buffer, "%d %lx\n", KEY_CHANGED, src->vpn_ip);

  if((write(cl->meta_socket, buffer, buflen)) < 0)
    {
      syslog(LOG_ERR, "send failed: %s:%d: %m", __FILE__, __LINE__);
      return -1;
    }
cp
  return 0;
}

void send_key_changed2(void)
{
  conn_list_t *p;
cp
  for(p = conn_list; p != NULL; p = p->next)
    if(p->status.meta && p->protocol_version > PROT_3)
      send_key_changed(p, myself);
cp
}

int send_basic_info(conn_list_t *cl)
{
cp
  if(debug_lvl > 2)
    syslog(LOG_DEBUG, "Send BASIC_INFO to " IP_ADDR_S,
	   IP_ADDR_V(cl->real_ip));

  buflen = sprintf(buffer, "%d %d %lx/%lx:%x\n", BASIC_INFO, PROT_CURRENT, myself->vpn_ip, myself->vpn_mask, myself->port);

  if((write(cl->meta_socket, buffer, buflen)) < 0)
    {
      syslog(LOG_ERR, "send failed: %s:%d: %m", __FILE__, __LINE__);
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

  if(debug_lvl > 2)
    syslog(LOG_DEBUG, "Send PASSPHRASE %s to " IP_ADDR_S,
	   tmp.phrase, IP_ADDR_V(cl->vpn_ip));

  buflen = snprintf(buffer, MAXBUFSIZE, "%d %s\n", PASSPHRASE, tmp.phrase);

  if((write(cl->meta_socket, buffer, buflen)) < 0)
    {
      syslog(LOG_ERR, "send failed: %s:%d: %m", __FILE__, __LINE__);
      return -1;
    }
cp
  return 0;
}

int send_public_key(conn_list_t *cl)
{
cp
  if(debug_lvl > 2)
    syslog(LOG_DEBUG, "Send PUBLIC_KEY %s to " IP_ADDR_S,
	   my_public_key_base36, IP_ADDR_V(cl->vpn_ip));

  buflen = sprintf(buffer, "%d %s\n", PUBLIC_KEY, my_public_key_base36);

  if((write(cl->meta_socket, buffer, buflen)) < 0)
    {
      syslog(LOG_ERR, "send failed: %s:%d: %m", __FILE__, __LINE__);
      return -1;
    }
cp
  return 0;
}

int send_calculate(conn_list_t *cl, char *k)
{
cp
  buflen = sprintf(buffer, "%d %s\n", CALCULATE, k);

  if((write(cl->meta_socket, buffer, buflen)) < 0)
    {
      syslog(LOG_ERR, "send failed: %s:%d: %m", __FILE__, __LINE__);
      return -1;
    }
cp
  return 0;
}

int send_key_request(ip_t to)
{
  conn_list_t *fw;
cp
  fw = lookup_conn(to);
  if(!fw)
    {
      syslog(LOG_ERR, "Attempting to send key request to " IP_ADDR_S ", which does not exist?",
	     IP_ADDR_V(to));
      return -1;
    }

  if(debug_lvl > 2)
    syslog(LOG_DEBUG, "Sending out request for public key to " IP_ADDR_S,
	   IP_ADDR_V(fw->nexthop->vpn_ip));

  buflen = sprintf(buffer, "%d %lx %lx\n", REQ_KEY, to, myself->vpn_ip);

  if((write(fw->nexthop->meta_socket, buffer, buflen)) < 0)
    {
      syslog(LOG_ERR, "send failed: %s:%d: %m", __FILE__, __LINE__);
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
      syslog(LOG_ERR, "Attempting to send key answer to " IP_ADDR_S ", which does not exist?",
	     IP_ADDR_V(to));
      return -1;
    }

 if(debug_lvl > 2)
    syslog(LOG_DEBUG, "Sending public key to " IP_ADDR_S,
	   IP_ADDR_V(fw->nexthop->vpn_ip));

  buflen = sprintf(buffer, "%d %lx %lx %d %s\n", ANS_KEY, to, myself->vpn_ip, my_key_expiry, my_public_key_base36);

  if((write(fw->nexthop->meta_socket, buffer, buflen)) < 0)
    {
      syslog(LOG_ERR, "send failed: %s:%d: %m", __FILE__, __LINE__);
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
    if(p != new && p != source && p->status.meta)
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
    if(p != new && p->protocol_version > PROT_3)
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
  if(sscanf(cl->buffer, "%*d %d %lx/%lx:%hx", &cl->protocol_version, &cl->vpn_ip, &cl->vpn_mask, &cl->port) != 4)
    {
       syslog(LOG_ERR, "got bad BASIC_INFO request: %s", cl->buffer);
       return -1;
    }  

  if(cl->protocol_version != PROT_CURRENT)
    {
      syslog(LOG_ERR, "Peer uses incompatible protocol version %d.",
	     cl->protocol_version);
      return -1;
    }

  if(debug_lvl > 2)
    syslog(LOG_DEBUG, "got BASIC_INFO(%hd," IP_ADDR_S "," IP_ADDR_S ")", cl->port,
	   IP_ADDR_V(cl->vpn_ip), IP_ADDR_V(cl->vpn_mask));
  if(debug_lvl > 1)
    syslog(LOG_DEBUG, "Peer uses protocol version %d",
	   cl->protocol_version);

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

  cl->status.active = 0;
cp
  return 0;
}

int passphrase_h(conn_list_t *cl)
{
cp
  cl->pp=xmalloc(sizeof(*(cl->pp)));
  if(sscanf(cl->buffer, "%*d %as", &(cl->pp->phrase)) != 1)
    {
      syslog(LOG_ERR, "got bad PASSPHRASE request: %s", cl->buffer);
      return -1;
    }
  cl->pp->len = strlen(cl->pp->phrase);
    
  if(debug_lvl > 2)
    syslog(LOG_DEBUG, "got PASSPHRASE");

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
cp
  if(sscanf(cl->buffer, "%*d %as", &g_n) != 1)
    {
       syslog(LOG_ERR, "got bad PUBLIC_KEY request: %s", cl->buffer);
       return -1;
    }  

  if(debug_lvl > 2)
    syslog(LOG_DEBUG, "got PUBLIC_KEY %s",  g_n);

  if(verify_passphrase(cl, g_n))
    {
      /* intruder! */
      syslog(LOG_ERR, "Intruder: passphrase does not match.");
      return -1;
    }

  if(debug_lvl > 2)
    syslog(LOG_INFO, "Passphrase OK");

  if(cl->status.outgoing)
    send_public_key(cl);
  else
    send_ack(cl);

  cl->status.active = 1;
  notify_others(cl, NULL, send_add_host);
  notify_one(cl);
cp
  return 0;
}

int ack_h(conn_list_t *cl)
{
cp
  if(debug_lvl > 2)
    syslog(LOG_DEBUG, "got ACK");
  
  cl->status.active = 1;
  syslog(LOG_NOTICE, "Connection with %s activated.", cl->hostname);
cp
  return 0;
}

int termreq_h(conn_list_t *cl)
{
cp
  syslog(LOG_NOTICE, IP_ADDR_S " wants to quit", IP_ADDR_V(cl->vpn_ip));
  cl->status.termreq = 1;
  terminate_connection(cl);

  notify_others(cl, NULL, send_del_host);
cp
  return 0;
}

int timeout_h(conn_list_t *cl)
{
cp
  syslog(LOG_NOTICE, IP_ADDR_S " says it's gotten a timeout from us", IP_ADDR_V(cl->vpn_ip));
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
  if(sscanf(cl->buffer, "%*d %lx", &vpn_ip) != 1)
    {
       syslog(LOG_ERR, "got bad DEL_HOST request: %s", cl->buffer);
       return -1;
    }  

  if(debug_lvl > 2)
    syslog(LOG_DEBUG, "got DEL_HOST for " IP_ADDR_S,
	   IP_ADDR_V(vpn_ip));

  if(!(fw = lookup_conn(vpn_ip)))
    {
      syslog(LOG_ERR, "Somebody wanted to delete " IP_ADDR_S " which does not exist?",
	     IP_ADDR_V(vpn_ip));
      return 0;
    }

  notify_others(cl, fw, send_del_host);

  fw->status.termreq = 1;
  terminate_connection(fw);
cp
  return 0;
}

int ping_h(conn_list_t *cl)
{
cp
  if(debug_lvl > 3)
    syslog(LOG_DEBUG, "responding to ping from " IP_ADDR_S, IP_ADDR_V(cl->vpn_ip));
  cl->status.pinged = 0;
  cl->status.got_pong = 1;

  send_pong(cl);
cp
  return 0;
}

int pong_h(conn_list_t *cl)
{
cp
  if(debug_lvl > 3)
    syslog(LOG_DEBUG, "ok, got pong from " IP_ADDR_S, IP_ADDR_V(cl->vpn_ip));
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
  conn_list_t *ncn, *fw;
cp
  if(sscanf(cl->buffer, "%*d %lx %lx/%lx:%hx", &real_ip, &vpn_ip, &vpn_mask, &port) != 4)
    {
       syslog(LOG_ERR, "got bad ADD_HOST request: %s", cl->buffer);
       return -1;
    }  

  if(debug_lvl > 2)
    syslog(LOG_DEBUG, "Add host request from " IP_ADDR_S, IP_ADDR_V(cl->vpn_ip));
  if(debug_lvl > 3)
    syslog(LOG_DEBUG, "got ADD_HOST(" IP_ADDR_S "," IP_ADDR_S ",%hd)",
	   IP_ADDR_V(vpn_ip), IP_ADDR_V(vpn_mask), port);

  /*
    Suggestion of Hans Bayle
  */
  if((fw = lookup_conn(vpn_ip)))
    {
      notify_others(fw, cl, send_add_host);
      return 0;
    }

  ncn = new_conn_list();
  ncn->real_ip = real_ip;
  ncn->vpn_ip = vpn_ip;
  ncn->vpn_mask = vpn_mask;
  ncn->port = port;
  ncn->hostname = hostlookup(real_ip);
  ncn->nexthop = cl;
  ncn->next = conn_list;
  conn_list = ncn;
  ncn->status.active = 1;
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
  if(sscanf(cl->buffer, "%*d %lx %lx", &to, &from) != 2)
    {
       syslog(LOG_ERR, "got bad request: %s", cl->buffer);
       return -1;
    }  

  if(debug_lvl > 2)
    syslog(LOG_DEBUG, "got REQ_KEY from " IP_ADDR_S " for " IP_ADDR_S,
	   IP_ADDR_V(from), IP_ADDR_V(to));

  if((to & myself->vpn_mask) == (myself->vpn_ip & myself->vpn_mask))
    {  /* hey! they want something from ME! :) */
      send_key_answer(cl, from);
      return 0;
    }

  fw = lookup_conn(to);
  
  if(!fw)
    {
      syslog(LOG_ERR, "Attempting to forward key request to " IP_ADDR_S ", which does not exist?",
	     IP_ADDR_V(to));
      return -1;
    }

  if(debug_lvl > 3)
    syslog(LOG_DEBUG, "Forwarding request for public key to " IP_ADDR_S,
	   IP_ADDR_V(fw->nexthop->vpn_ip));
  
  cl->buffer[cl->reqlen-1] = '\n';
  
  if(write(fw->nexthop->meta_socket, cl->buffer, cl->reqlen) < 0)
    {
      syslog(LOG_ERR, "send failed: %s:%d: %m", __FILE__, __LINE__);
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
  if(sscanf(cl->buffer, "%*d %lx %lx %d %as", &to, &from, &expiry, &key) != 4)
    {
       syslog(LOG_ERR, "got bad ANS_KEY request: %s", cl->buffer);
       return -1;
    }  

  if(debug_lvl > 3)
    syslog(LOG_DEBUG, "got ANS_KEY from " IP_ADDR_S " for " IP_ADDR_S,
	   IP_ADDR_V(from), IP_ADDR_V(to));

  if(to == myself->vpn_ip)
    {  /* hey! that key's for ME! :) */
      if(debug_lvl > 2)
	syslog(LOG_DEBUG, "Yeah! key arrived. Now do something with it.");
      gk = lookup_conn(from);

      if(!gk)
        {
          syslog(LOG_ERR, "Receiving key from " IP_ADDR_S ", which does not exist?",
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
      syslog(LOG_ERR, "Attempting to forward key to " IP_ADDR_S ", which does not exist?",
	     IP_ADDR_V(to));
      return -1;
    }

  if(debug_lvl > 2)
    syslog(LOG_DEBUG, "Forwarding public key to " IP_ADDR_S,
	   IP_ADDR_V(fw->nexthop->vpn_ip));

  cl->buffer[cl->reqlen-1] = '\n';

  if((write(fw->nexthop->meta_socket, cl->buffer, cl->reqlen)) < 0)
    {
      syslog(LOG_ERR, "send failed: %s:%d: %m", __FILE__, __LINE__);
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
  if(sscanf(cl->buffer, "%*d %lx", &from) != 1)
    {
       syslog(LOG_ERR, "got bad ANS_KEY request: %s", cl->buffer);
       return -1;
    }  

  if(debug_lvl > 2)
    syslog(LOG_DEBUG, "got KEY_CHANGED from " IP_ADDR_S,
	   IP_ADDR_V(from));

  ik = lookup_conn(from);

  if(!ik)
    {
      syslog(LOG_ERR, "Got changed key from " IP_ADDR_S ", which does not exist?",
	     IP_ADDR_V(from));
      return -1;
    }

  ik->status.validkey = 0;
  ik->status.waitingforkey = 0;

  if(debug_lvl > 3)
    syslog(LOG_DEBUG, "Forwarding key invalidation request");

  notify_others(cl, ik, send_key_changed);
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
