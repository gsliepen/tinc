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

#include <utils.h>
#include <xalloc.h>

#include "conf.h"
#include "encr.h"
#include "net.h"
#include "netutl.h"
#include "protocol.h"

int send_ack(conn_list_t *cl)
{
  unsigned char tmp = ACK;
cp
  if(debug_lvl > 2)
    syslog(LOG_DEBUG, "Send ACK to %s", cl->hostname);

  syslog(LOG_NOTICE, "Connection with %s activated.", cl->hostname);
  if((write(cl->meta_socket, &tmp, sizeof(tmp))) < 0)
    {
      syslog(LOG_ERR, "send failed: %d:%d: %m", __FILE__, __LINE__);
      return -1;
    }
cp
  return 0;
}

int send_termreq(conn_list_t *cl)
{
  termreq_t tmp;
cp
  tmp.type = TERMREQ;
  tmp.vpn_ip = myself->vpn_ip;

  if(debug_lvl > 2)
    syslog(LOG_DEBUG, "Send TERMREQ(" IP_ADDR_S ") to " IP_ADDR_S, IP_ADDR_V(tmp.vpn_ip),
	   IP_ADDR_V(cl->vpn_ip));

  if((write(cl->meta_socket, &tmp, sizeof(tmp))) < 0)
    {
      syslog(LOG_ERR, "send failed: %s:%d: %m", __FILE__, __LINE__);
      return -1;
    }
cp
  return 0;
}

int send_timeout(conn_list_t *cl)
{
  termreq_t tmp;
cp
  tmp.type = PINGTIMEOUT;
  tmp.vpn_ip = myself->vpn_ip;

  if(debug_lvl > 2)
    syslog(LOG_DEBUG, "Send TIMEOUT(" IP_ADDR_S ") to " IP_ADDR_S, IP_ADDR_V(tmp.vpn_ip),
	   IP_ADDR_V(cl->vpn_ip));

  if((write(cl->meta_socket, &tmp, sizeof(tmp))) < 0)
    {
      syslog(LOG_ERR, "send failed: %s:%d: %m", __FILE__, __LINE__);
      return -1;
    }
cp
  return 0;
}

int send_del_host(conn_list_t *cl, conn_list_t *new_host)
{
  del_host_t tmp;
cp
  tmp.type = DEL_HOST;
  tmp.vpn_ip = new_host->vpn_ip;

  if(debug_lvl > 2)
    syslog(LOG_DEBUG, "Sending delete host %lx to " IP_ADDR_S,
	   tmp.vpn_ip, IP_ADDR_V(cl->vpn_ip));

  if((write(cl->meta_socket, &tmp, sizeof(tmp))) < 0)
    {
      syslog(LOG_ERR, "send failed: %s:%d: %m", __FILE__, __LINE__);
      return -1;
    }
cp
  return 0;
}

int send_ping(conn_list_t *cl)
{
  unsigned char tmp = PING;
cp
  if(debug_lvl > 3)
    syslog(LOG_DEBUG, "pinging " IP_ADDR_S, IP_ADDR_V(cl->vpn_ip));

  if((write(cl->meta_socket, &tmp, sizeof(tmp))) < 0)
    {
      syslog(LOG_ERR, "send failed: %s:%d: %m", __FILE__, __LINE__);
      return -1;
    }
cp
  return 0;
}

int send_pong(conn_list_t *cl)
{
  unsigned char tmp = PONG;
cp
  if((write(cl->meta_socket, &tmp, sizeof(tmp))) < 0)
    {
      syslog(LOG_ERR, "send failed: %s:%d: %m", __FILE__, __LINE__);
      return -1;
    }
cp
  return 0;
}

int send_add_host(conn_list_t *cl, conn_list_t *new_host)
{
  add_host_t tmp;
cp
  tmp.type = ADD_HOST;
  tmp.real_ip = new_host->real_ip;
  tmp.vpn_ip = new_host->vpn_ip;
  tmp.vpn_mask = new_host->vpn_mask;
  tmp.portnr = new_host->port;

  if(debug_lvl > 2)
    syslog(LOG_DEBUG, "Sending add host (%lx/%lx %lx:%hd) to " IP_ADDR_S,
	   tmp.vpn_ip, tmp.vpn_mask, tmp.real_ip, tmp.portnr,
	   IP_ADDR_V(cl->vpn_ip));

  if((write(cl->meta_socket, &tmp, sizeof(tmp))) < 0)
    {
      syslog(LOG_ERR, "send failed: %s:%d: %m", __FILE__, __LINE__);
      return -1;
    }
cp
  return 0;
}

int send_key_changed(conn_list_t *cl, conn_list_t *src)
{
  key_changed_t tmp;
cp
  tmp.type = KEY_CHANGED;
  tmp.from = src->vpn_ip;

  if(debug_lvl > 2)
    syslog(LOG_DEBUG, "Sending KEY_CHANGED (%lx) to " IP_ADDR_S,
	   tmp.from, IP_ADDR_V(cl->vpn_ip));

  if((write(cl->meta_socket, &tmp, sizeof(tmp))) < 0)
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
  basic_info_t tmp;
cp
  tmp.type = BASIC_INFO;
  tmp.protocol = PROT_CURRENT;

  tmp.portnr = myself->port;
  tmp.vpn_ip = myself->vpn_ip;
  tmp.vpn_mask = myself->vpn_mask;

  if(debug_lvl > 2)
    syslog(LOG_DEBUG, "Send BASIC_INFO(%d,%hd," IP_ADDR_S "," IP_ADDR_S ") to " IP_ADDR_S,
	   tmp.protocol, tmp.portnr, IP_ADDR_V(tmp.vpn_ip), IP_ADDR_V(tmp.vpn_mask),
	   IP_ADDR_V(cl->real_ip));

  if((write(cl->meta_socket, &tmp, sizeof(tmp))) < 0)
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
  tmp.type = PASSPHRASE;
  encrypt_passphrase(&tmp);

  if(debug_lvl > 2)
    syslog(LOG_DEBUG, "Send PASSPHRASE(%hd,...) to " IP_ADDR_S, tmp.len,
	   IP_ADDR_V(cl->vpn_ip));

  if((write(cl->meta_socket, &tmp, tmp.len+3)) < 0)
    {
      syslog(LOG_ERR, "send failed: %s:%d: %m", __FILE__, __LINE__);
      return -1;
    }
cp
  return 0;
}

int send_public_key(conn_list_t *cl)
{
  public_key_t *tmp;
cp
  tmp = (public_key_t*)xmalloc(strlen(my_public_key_base36)+sizeof(*tmp));
  tmp->type = PUBLIC_KEY;
  tmp->len = strlen(my_public_key_base36);
  strcpy(&tmp->key, my_public_key_base36);

  if(debug_lvl > 2)
    syslog(LOG_DEBUG, "Send PUBLIC_KEY(%hd,%s) to " IP_ADDR_S, tmp->len, &tmp->key,
	   IP_ADDR_V(cl->vpn_ip));

  if((write(cl->meta_socket, tmp, tmp->len+sizeof(*tmp))) < 0)
    {
      syslog(LOG_ERR, "send failed: %s:%d: %m", __FILE__, __LINE__);
      return -1;
    }
cp
  return 0;
}

int send_calculate(conn_list_t *cl, char *k)
{
  calculate_t *tmp;
cp
  tmp = xmalloc(strlen(k)+sizeof(*tmp));
  tmp->type = CALCULATE;
  tmp->len = strlen(k);
  strcpy(&tmp->key, k);

  if((write(cl->meta_socket, tmp, tmp->len+sizeof(*tmp))) < 0)
    {
      syslog(LOG_ERR, "send failed: %s:%d: %m", __FILE__, __LINE__);
      return -1;
    }
cp
  return 0;
}

int send_key_request(ip_t to)
{
  key_req_t *tmp;
  conn_list_t *fw;
cp
  tmp = xmalloc(sizeof(*tmp));
  tmp->type = REQ_KEY;
  tmp->to = to;
  tmp->from = myself->vpn_ip;
  tmp->len = 0;

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
  if(write(fw->nexthop->meta_socket, tmp, sizeof(*tmp)) < 0)
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
  key_req_t *tmp;
  conn_list_t *fw;
cp
  tmp = xmalloc(sizeof(*tmp)+strlen(my_public_key_base36));
  tmp->type = ANS_KEY;
  tmp->to = to;
  tmp->from = myself->vpn_ip;
  tmp->expiry = my_key_expiry;
  tmp->len = strlen(my_public_key_base36);
  strcpy(&tmp->key, my_public_key_base36);

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
  if(write(fw->nexthop->meta_socket, tmp, sizeof(*tmp)+tmp->len) < 0)
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
    if(p != new && p != source && p->status.meta && p->protocol_version > PROT_3)
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

int basic_info_h(conn_list_t *cl, unsigned char *d, int len)
{
  basic_info_t *tmp = (basic_info_t*)d;
cp
  cl->protocol_version = tmp->protocol;
  cl->port = tmp->portnr;
  cl->vpn_ip = tmp->vpn_ip;
  cl->vpn_mask = tmp->vpn_mask;

  if(cl->protocol_version < PROT_CURRENT)
    {
      syslog(LOG_ERR, "Peer uses protocol version %d which is too old.",
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

int passphrase_h(conn_list_t *cl, unsigned char *d, int len)
{
  passphrase_t *tmp = (passphrase_t*)d;
cp
  cl->pp = xmalloc(tmp->len+3);
  memcpy(cl->pp, tmp, tmp->len+3);

  if(debug_lvl > 2)
    syslog(LOG_DEBUG, "got PASSPHRASE(%hd,...)", cl->pp->len);

  if(cl->status.outgoing)
    send_passphrase(cl);
  else
    send_public_key(cl);
cp
  return 0;
}

int public_key_h(conn_list_t *cl, unsigned char *d, int len)
{
  char *g_n;
  public_key_t *tmp = (public_key_t*)d;
cp
  if(debug_lvl > 2)
    syslog(LOG_DEBUG, "got PUBLIC_KEY(%hd,%s)", tmp->len, &tmp->key);

  g_n = xmalloc(tmp->len+1);
  strcpy(g_n, &tmp->key);

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

int ack_h(conn_list_t *cl, unsigned char *d, int len)
{
cp
  if(debug_lvl > 2)
    syslog(LOG_DEBUG, "got ACK");
  
  cl->status.active = 1;
  syslog(LOG_NOTICE, "Connection with %s activated.", cl->hostname);

  /*
                        === FIXME ===
    Now I'm going to cheat. The meta protocol is actually
    a stream of requests, that may come in in the same TCP
    packet. This is the only place that it will happen,
    though.
    I may change it in the future, if it appears that this
    is not retainable.
  */
  if(len > 1) /* An ADD_HOST follows */
    {
      if(request_handlers[d[1]] == NULL)
	syslog(LOG_ERR, "Unknown request %d.", d[1]);
      if(request_handlers[d[1]](cl, d + 1, len - 1) < 0)
	return -1;
    }
cp
  return 0;
}

int termreq_h(conn_list_t *cl, unsigned char *d, int len)
{
cp
  syslog(LOG_NOTICE, IP_ADDR_S " wants to quit", IP_ADDR_V(cl->vpn_ip));
  cl->status.termreq = 1;
  terminate_connection(cl);

  notify_others(cl, NULL, send_del_host);
cp
  return 0;
}

int timeout_h(conn_list_t *cl, unsigned char *d, int len)
{
cp
  syslog(LOG_NOTICE, IP_ADDR_S " says it's gotten a timeout from us", IP_ADDR_V(cl->vpn_ip));
  cl->status.termreq = 1;
  terminate_connection(cl);
cp
  return 0;
}

int del_host_h(conn_list_t *cl, unsigned char *d, int len)
{
  del_host_t *tmp = (del_host_t*)d;
  conn_list_t *fw;
cp
  if(debug_lvl > 2)
    syslog(LOG_DEBUG, "got DEL_HOST for " IP_ADDR_S,
	   IP_ADDR_V(tmp->vpn_ip));

  if(!(fw = lookup_conn(tmp->vpn_ip)))
    {
      syslog(LOG_ERR, "Somebody wanted to delete " IP_ADDR_S " which does not exist?",
	     IP_ADDR_V(tmp->vpn_ip));
      return 0;
    }

  notify_others(cl, fw, send_del_host);

  fw->status.termreq = 1;
  terminate_connection(fw);
cp
  return 0;
}

int ping_h(conn_list_t *cl, unsigned char *d, int len)
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

int pong_h(conn_list_t *cl, unsigned char *d, int len)
{
cp
  if(debug_lvl > 3)
    syslog(LOG_DEBUG, "ok, got pong from " IP_ADDR_S, IP_ADDR_V(cl->vpn_ip));
  cl->status.got_pong = 1;
cp
  return 0;
}

int add_host_h(conn_list_t *cl, unsigned char *d, int len)
{
  add_host_t *tmp = (add_host_t*)d;
  conn_list_t *ncn, *fw;
cp
  if(debug_lvl > 2)
    syslog(LOG_DEBUG, "Add host request from " IP_ADDR_S, IP_ADDR_V(cl->vpn_ip));
  if(debug_lvl > 3)
    syslog(LOG_DEBUG, "got ADD_HOST(" IP_ADDR_S "," IP_ADDR_S ",%hd)",
	   IP_ADDR_V(tmp->vpn_ip), IP_ADDR_V(tmp->vpn_mask), tmp->portnr);

  /*
    Suggestion of Hans Bayle
  */
  if((fw = lookup_conn(tmp->vpn_ip)))
    {
      notify_others(fw, cl, send_add_host);
      return 0;
    }

  ncn = new_conn_list();
  ncn->real_ip = tmp->real_ip;
  ncn->vpn_ip = tmp->vpn_ip;
  ncn->vpn_mask = tmp->vpn_mask;
  ncn->port = tmp->portnr;
  ncn->hostname = hostlookup(tmp->real_ip);
  ncn->nexthop = cl;
  ncn->next = conn_list;
  conn_list = ncn;
  ncn->status.active = 1;
  notify_others(ncn, cl, send_add_host);

  /*
    again, i'm cheating here. see the comment in ack_h.
    Naughty zarq! Now you see what cheating will get you... [GS]
  */
  if(len > sizeof(*tmp)) /* Another ADD_HOST follows */
    {
      if(request_handlers[d[sizeof(*tmp)]] == NULL)
	syslog(LOG_ERR, "Unknown request %d.", d[sizeof(*tmp)]);
      if(request_handlers[d[sizeof(*tmp)]](cl, d + sizeof(*tmp), len - sizeof(*tmp)) < 0)
	return -1;
    }
cp
  return 0;
}

int req_key_h(conn_list_t *cl, unsigned char *d, int len)
{
  key_req_t *tmp = (key_req_t*)d;
  conn_list_t *fw;
cp
  if(debug_lvl > 2)
    syslog(LOG_DEBUG, "got REQ_KEY from " IP_ADDR_S " for " IP_ADDR_S,
	   IP_ADDR_V(tmp->from), IP_ADDR_V(tmp->to));

  if((tmp->to & myself->vpn_mask) == (myself->vpn_ip & myself->vpn_mask))
    {  /* hey! they want something from ME! :) */
      send_key_answer(cl, tmp->from);
      return 0;
    }

  fw = lookup_conn(tmp->to);
  
  if(!fw)
  {
    syslog(LOG_ERR, "Attempting to forward key request to " IP_ADDR_S ", which does not exist?",
	   IP_ADDR_V(tmp->to));
    return -1;
  }

  if(debug_lvl > 3)
    syslog(LOG_DEBUG, "Forwarding request for public key to " IP_ADDR_S,
	   IP_ADDR_V(fw->nexthop->vpn_ip));
  if(write(fw->nexthop->meta_socket, tmp, sizeof(*tmp)) < 0)
    {
      syslog(LOG_ERR, "send failed: %s:%d: %m", __FILE__, __LINE__);
      return -1;
    }
cp
  return 0;
}

void set_keys(conn_list_t *cl, key_req_t *k)
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
  cl->public_key->length = k->len;
  cl->public_key->expiry = k->expiry;
  cl->public_key->key = xmalloc(k->len + 1);
  strcpy(cl->public_key->key, &(k->key));

  ek = make_shared_key(&(k->key));
  if(!cl->key)
    {
      cl->key = xmalloc(sizeof(*cl->key));
      cl->key->key = NULL;
    }
  if(cl->key->key)
    free(cl->key->key);
  cl->key->length = strlen(ek);
  cl->key->expiry = k->expiry;
  cl->key->key = xmalloc(strlen(ek) + 1);
  strcpy(cl->key->key, ek);
cp
}

int ans_key_h(conn_list_t *cl, unsigned char *d, int len)
{
  key_req_t *tmp = (key_req_t*)d;
  conn_list_t *fw, *gk;
cp
  if(debug_lvl > 3)
    syslog(LOG_DEBUG, "got ANS_KEY from " IP_ADDR_S " for " IP_ADDR_S,
	   IP_ADDR_V(tmp->from), IP_ADDR_V(tmp->to));

  if(tmp->to == myself->vpn_ip)
    {  /* hey! that key's for ME! :) */
      if(debug_lvl > 2)
	syslog(LOG_DEBUG, "Yeah! key arrived. Now do something with it.");
      gk = lookup_conn(tmp->from);

      if(!gk)
        {
          syslog(LOG_ERR, "Receiving key from " IP_ADDR_S ", which does not exist?",
	         IP_ADDR_V(tmp->from));
          return -1;
        }

      set_keys(gk, tmp);
      gk->status.validkey = 1;
      gk->status.waitingforkey = 0;
      flush_queues(gk);
      return 0;
    }

  fw = lookup_conn(tmp->to);
  
  if(!fw)
  {
    syslog(LOG_ERR, "Attempting to forward key to " IP_ADDR_S ", which does not exist?",
	   IP_ADDR_V(tmp->to));
    return -1;
  }

  if(debug_lvl > 2)
    syslog(LOG_DEBUG, "Forwarding public key to " IP_ADDR_S,
	   IP_ADDR_V(fw->nexthop->vpn_ip));
  if(write(fw->nexthop->meta_socket, tmp, sizeof(*tmp)+tmp->len) < 0)
    {
      syslog(LOG_ERR, "send failed: %s:%d: %m", __FILE__, __LINE__);
      return -1;
    }
cp
  return 0;
}

int key_changed_h(conn_list_t *cl, unsigned char *d, int len)
{
  key_changed_t *tmp = (key_changed_t*)d;
  conn_list_t *ik;
cp
  if(debug_lvl > 2)
    syslog(LOG_DEBUG, "got KEY_CHANGED from " IP_ADDR_S,
	   IP_ADDR_V(tmp->from));

  ik = lookup_conn(tmp->from);

  if(!ik)
    {
      syslog(LOG_ERR, "Got changed key from " IP_ADDR_S ", which does not exist?",
	     IP_ADDR_V(tmp->from));
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

int (*request_handlers[256])(conn_list_t*, unsigned char*, int) = {
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
