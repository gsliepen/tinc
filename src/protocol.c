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

    $Id: protocol.c,v 1.28.4.29 2000/09/11 10:05:34 guus Exp $
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

#include <netinet/in.h>

#include "conf.h"
#include "encr.h"
#include "net.h"
#include "netutl.h"
#include "protocol.h"

#include "system.h"

/* Generic outgoing request routine - takes care of logging and error detection as well */

int send_request(conn_list_t *cl, const char *format, int request, /*args*/ ...)
{
  va_list args;
  char *buffer = NULL;
cp
  if(debug_lvl >= DEBUG_PROTOCOL)
    syslog(LOG_DEBUG, _("Sending %s to %s (%s)"), requestname[request], cl->id, cl->hostname);

  va_start(args, format);
  len = vasprintf(&buffer, format, args);
  va_end(args);

  if(len < 0 || !buffer)
    {
      syslog(LOG_ERR, _("Error during vasprintf(): %m"));
      return -1;
    }

  if(debug_lvl >= DEBUG_META)
    syslog(LOG_DEBUG, _("Sending meta data to %s (%s): %s"), cl->id, cl->hostname, buffer);

  if(cl->status.encryptout)
    {
      /* FIXME: Do encryption */
    }

  if((write(cl->meta_socket, buffer, buflen)) < 0)
    {
      syslog(LOG_ERR, _("Sending meta data failed:  %m"));
      return -1;
    }
cp  
}

/* Connection protocol:

   Client               Server
   send_id(*)
                        send_challenge
   send_chal_reply(*)                   
                        send_id
   send_challenge
                        send_chal_reply
   send_ack
			send_ack

   (*) Unencrypted.
*/      

int send_id(conn_list_t *cl)
{
cp
  return send_request(cl, "%d %s %d %s", ID, myself->id, myself->version, opt2str(myself->options));
}

int id_h(conn_list_t *cl)
{
  conn_list_t *old;
  char *options;
cp
  if(sscanf(cl->buffer, "%*d %as %d %as", &cl->id, &cl->version, &options) != 3)
    {
       syslog(LOG_ERR, _("Got bad ID from %s"), cl->hostname);
       return -1;
    }
    
  /* Check if version matches */
  
  if(cl->version != myself->version)
    {
      syslog(LOG_ERR, _("Peer %s uses incompatible version %d"), cl->hostname, cl->min_version, cl->max_version);
      return -1;
    }

  /* Check if option string is valid */
  
  if((cl->options = str2opt(options)) == -1)
    {
      syslog(LOG_ERR, _("Peer %s uses invalid option string"), cl->hostname);
      return -1;
    }
    
  /* Check if identity is a valid name */
  
  if(!check_id(cl->id))
    {
      syslog(LOG_ERR, _("Peer %s uses invalid identity name"), cl->hostname);
      return -1;
    }
    
  /* Load information about peer */
  
  if(!read_id(cl))
    {
      syslog(LOG_ERR, _("Peer %s had unknown identity (%s)"), cl->hostname, cl->id);
      return -1;
    }


  /* First check if the host we connected to is already in our
     connection list. If so, we are probably making a loop, which
     is not desirable.
   */

  if(cl->status.outgoing)
    {
      if((old=lookup_id(cl->id)))
        {
          if(debug_lvl > DEBUG_CONNECTIONS)
            syslog(LOG_NOTICE, _("Uplink %s (%s) is already in our connection list"), cl->id, cl->hostname);
          cl->status.outgoing = 0;
          old->status.outgoing = 1;
          terminate_connection(cl);
          return 0;
        }
    }

  /* Since we know the identity now, we can encrypt the meta channel */
  
  cl->status.encryptout = 1;

  /* Send a challenge to verify the identity */

  cl->allow_request = CHAL_REPLY;
cp
  return send_challenge(cl);
}

int send_challenge(conn_list_t *cl)
{
  char *buffer;
  int keylength;
  int x;
cp
  if(cl->chal_hash)
    free(cl->chal_hash);
  
  /* Allocate buffers for the challenge and the hash */
  
  cl->chal_hash = xmalloc(SHA_DIGEST_LEN);
  keylength = BN_num_bytes(cl->metakey.n);
  buffer = xmalloc(keylength*2);

  /* Copy random data and the public key to the buffer */
  
  RAND_bytes(buffer, keylength);
  BN_bn2bin(cl->metakey.n, buffer+keylength);

  /* Calculate the hash from that */

  SHA1(buffer, keylength*2, cl->chal_hash);

  /* Convert the random data to a hexadecimal formatted string */

  bin2hex(buffer,buffer,keylength);
  buffer[keylength*2] = '\0';

  /* Send the challenge */
  
  cl->allow_request = CHAL_REPLY;
  x = send_request(cl, "%d %s", CHALLENGE, buffer);
  free(buffer);
cp
  return x;
}

int challenge_h(conn_list_t *cl)
{
  char *challenge;
cp
  if(sscanf(cl->buffer, "%*d %as", &cl->id, &challenge) != 1)
    {
       syslog(LOG_ERR, _("Got bad CHALLENGE from %s (%s)"), cl->id, cl->hostname);
       return -1;
    }

  /* Rest is done by send_chal_reply() */
  
  x = send_chal_reply(cl, challenge);
  free(challenge);
cp
  return x;
}

int send_chal_reply(conn_list_t *cl, char *challenge)
{
  char *buffer;
  int keylength;
  char *hash;
  int x;
cp
  keylength = BN_num_bytes(myself->meyakey.n);

  /* Check if the length of the challenge is all right */

  if(strlen(challenge) != keylength*2)
    {
      syslog(LOG_ERROR, _("Intruder: wrong challenge length from %s (%s)"), cl->id, cl->hostname);
      return -1;
    }

  /* Allocate buffers for the challenge and the hash */
  
  buffer = xmalloc(keylength*2);
  hash = xmalloc(SHA_DIGEST_LEN*2+1);

  /* Copy the incoming random data and our public key to the buffer */

  hex2bin(challenge, buffer, keylength); 
  BN_bn2bin(myself->metakey.n, buffer+keylength);

  /* Calculate the hash from that */
  
  SHA1(buffer, keylength*2, hash);
  free(buffer);

  /* Convert the hash to a hexadecimal formatted string */

  bin2hex(hash,hash,SHA_DIGEST_LEN);
  hash[SHA_DIGEST_LEN*2] = '\0';

  /* Send the reply */

  if(cl->status.outgoing)
    cl->allow_resuest = ID;
  else
    cl->allow_request = ACK;

  x = send_request(cl, "%d %s", CHAL_REPLY, hash);
  free(hash);
cp
  return x;
} 

int chal_reply_h(conn_list_t *cl)
{
  char *hash;
cp
  if(sscanf(cl->buffer, "%*d %as", &cl->id, &hash) != 2)
    {
       syslog(LOG_ERR, _("Got bad CHAL_REPLY from %s (%s)"), cl->id, cl->hostname);
       return -1;
    }

  /* Check if the length of the hash is all right */
  
  if(strlen(hash) != SHA_DIGEST_LEN*2)
    {
      syslog(LOG_ERROR, _("Intruder: wrong challenge reply length from %s (%s)"), cl->id, cl->hostname);
      return -1;
    }
    
  /* Convert the hash to binary format */
  
  hex2bin(hash, hash, SHA_DIGEST_LEN);
  
  /* Verify the incoming hash with the calculated hash */
  
  if{!memcmp(hash, cl->chal_hash, SHA_DIGEST_LEN)}
    {
      syslog(LOG_ERROR, _("Intruder: wrong challenge reply from %s (%s)"), cl->id, cl->hostname);
      return -1;
    }

  /* Identity has now been positively verified.
     If we are accepting this new connection, then send our identity,
     if we are making this connecting, acknowledge.
   */
   
  free(hash);
  free(cl->chal_hash);

cp
  if(cl->status.outgoing)
    {
      cl->allow_request = ACK;
      return send_ack(cl);
    }
  else
    {
      cl->allow_request = CHALLENGE;
      return send_id(cl);
    }
}

int send_ack(conn_list_t *cl)
{
cp
  return send_request(cl, "%d", ACK);
}

int ack_h(conn_list_t *cl)
{
  conn_list_t old;
cp
  /* Okay, before we active the connection, we check if there is another entry
     in the connection list with the same vpn_ip. If so, it presumably is an
     old connection that has timed out but we don't know it yet.
   */

  while((old = lookup_id(cl->id))) 
    {
      if(debug_lvl > DEBUG_CONNECTIONS)
        syslog(LOG_NOTICE, _("Removing old entry for %s at %s in favour of new connection from %s"),
        cl->id, old->hostname, cl->hostname);
      old->status.active = 0;
      terminate_connection(old);
    }

  /* Activate this connection */

  cl->allow_request = ALL;
  cl->status.active = 1;

  if(debug_lvl > DEBUG_CONNECTIONS)
    syslog(LOG_NOTICE, _("Connection with %s (%s) activated"), cl->id, cl->hostname);

  /* Exchange information about other tinc daemons */

  notify_others(cl, NULL, send_add_host);
  notify_one(cl);

  upstreamindex = 0;

cp
  if(cl->status.outgoing)
    return 0;
  else
    return send_ack(cl);
}

/* Address and subnet information exchange */

int send_add_subnet(conn_list_t *cl, conn_list_t *other, subnet_t *subnet)
{
cp
  return send_request(cl, "%d %s %d %s", ADD_SUBNET, other->id, subnet->type, net2str(subnet));
}

int add_subnet_h(conn_list_t *cl)
{
}

int send_del_subnet(conn_list_t *cl, conn_list_t *other, subnet_t *subnet)
{
cp
  return send_request(cl, "%d %s %d %s", DEL_SUBNET, other->id, subnet->type, net2str(subnet));
}

int del_subnet_h(conn_list_t *cl)
{
}

/* New and closed connections notification */

int send_add_host(conn_list_t *cl, conn_list_t *other)
{
cp
  return send_request(cl, "%d %s %lx:%d %s", ADD_HOST, other->id, other->address, other->port, opt2str(other->options));
}

int add_host_h(conn_list_t *cl)
{
  char *options;
  conn_list_t *old, *new;
cp
  new = new_conn_list();

  if(sscanf(cl->buffer, "%*d %as %lx:%d %as", &new->id, &new->address, &new->port, &options) != 4)
    {
       syslog(LOG_ERR, _("Got bad ADD_HOST from %s (%s)"), cl->id, cl->hostname);
       return -1;
    }  

  /* Check if option string is valid */
  
  if((new->options = str2opt(options) == -1)
    {
      syslog(LOG_ERR, _("Got bad ADD_HOST from %s (%s): invalid option string"), cl->hostname);
      return -1;
    }

  /* Check if identity is a valid name */
  
  if(!check_id(new->id))
    {
      syslog(LOG_ERR, _("Got bad ADD_HOST from %s (%s): invalid identity name"), cl->id, cl->hostname);
      return -1;
    }
    
  /* Check if somebody tries to add ourself */
  
  if(!strcmp(new->id, myself->id))
    {
      syslog(LOG_ERR, _("Warning: got ADD_HOST from %s (%s) for ourself, restarting"), cl->id, cl->hostname);
      sighup = 1;
      return 0;
    }

  /* Fill in more of the new conn_list structure */

  new->hostname = hostlookup(htonl(new->address));
  
  /* Check if the new host already exists in the connnection list */

  if((old = lookup_id(id))
    {
      if((new->address == old->address) && (new->port == old->port))
        {
          if(debug_lvl > DEBUG_CONNECTIONS)
            syslog(LOG_NOTICE, _("Got duplicate ADD_HOST for %s (%s) from %s (%s)"), old->id, old->hostname, new->id, new->hostname);
	  return 0;
        }
      else
        {
          if(debug_lvl > DEBUG_CONNECTIONS)
            syslog(LOG_NOTICE, _("Removing old entry for %s (%s)"), old->id, old->hostname);
          old->status.active = 0;
          terminate_connection(old);
        }
    }

  /* Fill in rest of conn_list structure */

  new->nexthop = cl;
  new->status.active = 1;
  
  /* Hook it up into the conn_list */

  conn_list_add(conn_list, new);

  /* Tell the rest about the new host */
  
  notify_others(new, cl, send_add_host);
  
cp
  return 0;
}

int send_del_host(conn_list_t *cl, conn_list_t *other)
{
cp
  return send_request(cl, "%d %s %lx:%d", DEL_HOST, other->id, other->address, other->port);
}

int del_host_h(conn_list_t *cl)
{
  char *id;
  ip_t address;
  port_t port;
  conn_list_t *old;
cp
  if(sscanf(cl->buffer, "%*d %as %lx:%d", &id, &address, &port) != 3)
    {
       syslog(LOG_ERR, _("Got bad DEL_HOST from %s (%s)"), cl->id, cl->hostname);
       return -1;
    }  

  /* Check if somebody tries to delete ourself */
  
  if(!strcmp(id, myself->id))
    {
      syslog(LOG_ERR, _("Warning: got DEL_HOST from %s (%s) for ourself, restarting"), cl->id, cl->hostname);
      sighup = 1;
      return 0;
    }

  /* Check if the new host already exists in the connnection list */

  if((old = lookup_id(id))
    {
      if((address == old->address) && (port == old->port))
        {
          notify_others(old, cl, send_del_host);

          fw->status.termreq = 1;
          fw->status.active = 0;

          terminate_connection(fw);
cp
          return 0;
        }
    }

  if(debug_lvl > DEBUG_CONNECTIONS)
    {
      syslog(LOG_NOTICE, _("Got DEL_HOST for %s from %s (%s) which is not in our connection list"), id, cl->id, cl->hostname);
    }
cp
  return 0;
}

/* Status and error notification routines */

int send_status(conn_list_t *cl, int statusno, char *statusstring)
{
cp
  if(!statusstring)
    statusstring = status_text[statusno];
cp
  return send_request(cl, "%d %d %s", STATUS, statusno, statusstring);
}

int status_h(conn_list_t *cl)
{
  int statusno;
  char *statusstring;
cp
  if(sscanf(cl->buffer, "%*d %d %as", &statusno, &statusstring) != 2)
    {
       syslog(LOG_ERR, _("Got bad STATUS from %s (%s)"), cl->id, cl->hostname);
       return -1;
    }

  if(debug_lvl > DEBUG_STATUS)
    {
      syslog(LOG_NOTICE, _("Status message from %s (%s): %s: %s"), cl->id, cl->hostname, status_text[statusno], statusstring);
    }

cp
  free(statusstring);
  return 0;
}

int send_error(conn_list_t *cl, int errno, char *errstring)
{
cp
  if(!errorstring)
    errorstring = error_text[errno];
  return send_request(cl, "%d %d %s", ERROR, errno, errstring);
}

int error_h(conn_list_t *cl)
{
  int errno;
  char *errorstring;
cp
  if(sscanf(cl->buffer, "%*d %d %as", &errno, &errorstring) != 2)
    {
       syslog(LOG_ERR, _("Got bad error from %s (%s)"), cl->id, cl->hostname);
       return -1;
    }

  if(debug_lvl > DEBUG_error)
    {
      syslog(LOG_NOTICE, _("Error message from %s (%s): %s: %s"), cl->id, cl->hostname, error_text[errno], errorstring);
    }

  free(errorstring);
  cl->status.termreq = 1;
  terminate_connection(cl);
cp
  return 0;
}

int send_termreq(conn_list_t *cl)
{
cp
  return send_request(cl, "%d", TERMREQ);
}

int termreq_h(conn_list_t *cl)
{
cp
  cl->status.termreq = 1;
  terminate_connection(cl);
cp
  return 0;
}

/* Keepalive routines - FIXME: needs a closer look */

int send_ping(conn_list_t *cl)
{
  cl->status.pinged = 1;
cp
  return send_request(cl, "%d", PING);
}

int ping_h(conn_list_t *cl)
{
cp
  return send_pong(cl);
}

int send_pong(conn_list_t *cl)
{
cp
  return send_request(cl, "%d", PONG);
}

int pong_h(conn_list_t *cl)
{
cp
  cl->status.got_pong = 1;
cp
  return 0;
}

/* Key exchange */

int send_key_changed(conn_list_t *from, conn_list_t *cl)
{
  conn_list_t *p;
cp
  for(p = conn_list; p != NULL; p = p->next)
    {
      if(p!=cl && p->status.meta && p->status.active)
        send_request(p, "%d %s", KEY_CHANGED, from->id);
    }
cp
  return 0;
}

int key_changed_h(conn_list_t *cl)
{
  char *from_id;
  conn_list_t *from;
cp
  if(sscanf(cl->buffer, "%*d %as", &from_id) != 1)
    {
       syslog(LOG_ERR, _("Got bad KEY_CHANGED from %s (%s)"), cl->id, cl->hostname);
       return -1;
    }  

  if(!(from = lookup_id(from_id)))
    {
      syslog(LOG_ERR, _("Got KEY_CHANGED from %s (%s) origin %s which does not exist in our connection list"), cl->id, cl->hostname, from_id);
      free(from_id);
      return -1;
    }

  free(from_id);
    
  from->status.validkey = 0;
  from->status.waitingforkey = 0;
  
  send_key_changed(from, cl);
cp
  return 0;
}
  
int send_req_key(conn_list_t *from, conn_list_t *to)
{
cp
  return send_request(to->nexthop, "%d %s %s", REQ_KEY, from->id, to->id);
}

int req_key_h(conn_list_t *cl)
{
  char *from_id, *to_id;
  conn_list_t *from, *to;
cp
  if(sscanf(cl->buffer, "%*d %as %as", &from_id, &to_id) != 2)
    {
       syslog(LOG_ERR, _("Got bad REQ_KEY from %s (%s)"), cl->id, cl->hostname);
       return -1;
    }  

  if(!(from = lookup_id(from_id)))
    {
      syslog(LOG_ERR, _("Got REQ_KEY from %s (%s) origin %s which does not exist in our connection list"), cl->id, cl->hostname, from_id);
      free(from_id); free(to_id);
      return -1;
    }

  /* Check if this key request is for us */

  if(!strcmp(id, myself->strcmp))
    {
      send_ans_key(myself, from, myself->datakey);
    }
  else
    {
      if(!(to = lookup_id(to_id)))
        {
          syslog(LOG_ERR, _("Got REQ_KEY from %s (%s) destination %s which does not exist in our connection list"), cl->id, cl->hostname, to_id);
          free(from_id); free(to_id);
          return -1;
        }
      send_req_key(from, to);
    }

  free(from_id); free(to_id);
cp
  return 0;
}

int send_ans_key(conn_list_t *from, conn_list_t *to, char *datakey)
{
cp
  return send_request(to->nexthop, "%d %s %s %s", ANS_KEY, from->id, to->id, datakey);
}

int ans_key_h(conn_list_t *cl)
{
  char *from_id, *to_id, *datakey;
  int keylength;
  conn_list_t *from, *to;
cp
  if(sscanf(cl->buffer, "%*d %as %as %as", &from_id, &to_id, &datakey) != 3)
    {
       syslog(LOG_ERR, _("Got bad ANS_KEY from %s (%s)"), cl->id, cl->hostname);
       return -1;
    }  

  if(!(from = lookup_id(from_id)))
    {
      syslog(LOG_ERR, _("Got ANS_KEY from %s (%s) origin %s which does not exist in our connection list"), cl->id, cl->hostname, from_id);
      free(from_id); free(to_id); free(datakey);
      return -1;
    }

  /* Check if this key request is for us */

  if(!strcmp(id, myself->strcmp))
    {
      /* It is for us, convert it to binary and set the key with it. */
      
      keylength = strlen(datakey);
      
      if((keylength%2) || (keylength <= 0))
        {
          syslog(LOG_ERR, _("Got bad ANS_KEY from %s (%s) origin %s: invalid key"), cl->id, cl->hostname, from->id);
          free(from_id); free(to_id); free(datakey);
          return -1;
        }
      keylength /= 2;
      hex2bin(datakey, datakey, keylength);
      BF_set_key(cl->datakey, keylength, datakey);
    }
  else
    {
      if(!(to = lookup_id(to_id)))
        {
          syslog(LOG_ERR, _("Got ANS_KEY from %s (%s) destination %s which does not exist in our connection list"), cl->id, cl->hostname, to_id);
          free(from_id); free(to_id); free(datakey);
          return -1;
        }
      send_ans_key(from, to, datakey);
    }

  free(from_id); free(to_id); free(datakey);
cp
  return 0;
}

/* Old routines */

/*
  Notify all my direct connections of a new host
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
  Notify one connection of everything
  I have connected
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

/* "Complete overhaul". */

int (*request_handlers[])(conn_list_t*) = {
  id_h, challenge_h, chal_reply_h, ack_h,
  status_h, error_h, termreq_h,
  ping_h, pong_h,
  add_host_h, del_host_h,
  add_subnet_h, del_subnet_h,
  key_changed_h, req_key_h, ans_key_h,
};

char (*request_name[]) = {
  "ID", "CHALLENGE", "CHAL_REPLY", "ACK",
  "STATUS", "ERROR", "TERMREQ",
  "PING", "PONG",
  "ADD_HOST", "DEL_HOST",
  "ADD_SUBNET", "DEL_SUBNET",
  "KEY_CHANGED", "REQ_KEY", "ANS_KEY",
};
