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

    $Id: protocol.c,v 1.28.4.35 2000/09/22 16:20:07 guus Exp $
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

#include <openssl/sha.h>

#include "conf.h"
#include "encr.h"
#include "net.h"
#include "netutl.h"
#include "protocol.h"

#include "system.h"

int check_id(char *id)
{
  int i;

  for (i = 0; i < strlen(id); i++)
    {
      if(!isalpha(id[i]) && id[i] != '_')
        {
          return 0;
        }
    }

  return 1;
}

/* Generic outgoing request routine - takes care of logging and error detection as well */

int send_request(conn_list_t *cl, const char *format, int request, /*args*/ ...)
{
  va_list args;
  char buffer[MAXBUFSIZE+1];
  int len;

cp
  /* Use vsnprintf instead of vasprintf: faster, no memory fragmentation, cleanup is automatic,
     and there is a limit on the input buffer anyway */

  va_start(args, request);
  len = vsnprintf(buffer, MAXBUFSIZE+1, format, args);
  va_end(args);

  if(len < 0 || len > MAXBUFSIZE)
    {
      syslog(LOG_ERR, _("Output buffer overflow while sending %s to %s (%s)"), request_name[request], cl->name, cl->hostname);
      return -1;
    }

  if(debug_lvl >= DEBUG_PROTOCOL)
    syslog(LOG_DEBUG, _("Sending %s to %s (%s)"), request_name[request], cl->name, cl->hostname);
cp
  return send_meta(cl, buffer, length);
}


int send_meta(conn_list_t *cl, const char *buffer, int length)
{
cp
  if(debug_lvl >= DEBUG_META)
    syslog(LOG_DEBUG, _("Sending %d bytes of metadata to %s (%s): %s"), int length,
           cl->name, cl->hostname, buffer);

  if(cl->status.encryptin)
    {
      /* FIXME: Do encryption */
    }

  if(write(cl->meta_socket, buffer, length) < 0)
    {
      syslog(LOG_ERR, _("Sending meta data to %s (%s) failed: %m"), cl->name, cl->hostname);
      return -1;
    }
cp
  return 0;
}

int broadcast_meta(conn_list_t *cl, const char *buffer, int length)
{
  conn_list_t *p;
cp
  for(p = conn_list; p != NULL; p = p->next)
    if(p != cl && p->status.meta && p->status.active)
      send_meta(p, buffer, length);
cp
  return 0;
}

/* Connection protocol:

   Client               Server
   send_id(u)
                        send_challenge(R)
   send_chal_reply(H)
                        send_id(u)
   send_challenge(R)
                        send_chal_reply(H)
   ---------------------------------------
   Any negotations about the meta protocol
   encryption go here(u).
   ---------------------------------------
   send_ack(u)
                        send_ack(u)
   ---------------------------------------
   Other requests(E)...

   (u) Unencrypted,
   (R) RSA,
   (H) SHA1,
   (E) Encrypted with symmetric cipher.

   Part of the challenge is directly used to set the symmetric cipher key and the initial vector.
   Since a man-in-the-middle cannot decrypt the RSA challenges, this means that he cannot get or
   forge the key for the symmetric cipher.
*/

int send_id(conn_list_t *cl)
{
cp
  return send_request(cl, "%d %s %d %lx", ID, myself->name, myself->protocol_version, myself->options);
}

int id_h(conn_list_t *cl)
{
  conn_list_t *old;
cp
  if(sscanf(cl->buffer, "%*d %as %d %lx", &cl->name, &cl->protocol_version, &cl->options) != 3)
    {
       syslog(LOG_ERR, _("Got bad ID from %s"), cl->hostname);
       return -1;
    }

  /* Check if version matches */

  if(cl->protocol_version != myself->protocol_version)
    {
      syslog(LOG_ERR, _("Peer %s (%s) uses incompatible version %d"),
             cl->name, cl->hostname, cl->protocol_version);
      return -1;
    }

  /* Check if identity is a valid name */

  if(!check_id(cl->name))
    {
      syslog(LOG_ERR, _("Peer %s uses invalid identity name"), cl->hostname);
      return -1;
    }

  /* Load information about peer */

  if(!read_id(cl))
    {
      syslog(LOG_ERR, _("Peer %s had unknown identity (%s)"), cl->hostname, cl->name);
      return -1;
    }


  /* First check if the host we connected to is already in our
     connection list. If so, we are probably making a loop, which
     is not desirable.
   */

  if(cl->status.outgoing)
    {
      if((old = lookup_id(cl->name)))
        {
          if(debug_lvl > DEBUG_CONNECTIONS)
            syslog(LOG_NOTICE, _("Uplink %s (%s) is already in our connection list"), cl->name, cl->hostname);
          cl->status.outgoing = 0;
          old->status.outgoing = 1;
          terminate_connection(cl);
          return 0;
        }
    }

  /* Send a challenge to verify the identity */

  cl->allow_request = CHAL_REPLY;
cp
  return send_challenge(cl);
}

int send_challenge(conn_list_t *cl)
{
  char buffer[CHAL_LENGTH*2+1];
cp
  /* Allocate buffers for the challenge */

  if(!cl->hischallenge)
    cl->hischallenge = xmalloc(CHAL_LENGTH);

  /* Copy random data to the buffer */

  RAND_bytes(cl->hischallenge, CHAL_LENGTH);

  /* Convert the random data to a hexadecimal formatted string */

  bin2hex(cl->hischallenge,buffer,CHAL_LENGTH);
  buffer[keylength*2] = '\0';

  /* Send the challenge */

  cl->allow_request = CHAL_REPLY;
cp
  return send_request(cl, "%d %s", CHALLENGE, buffer);
}

int challenge_h(conn_list_t *cl)
{
  char *buffer;
cp
  if(sscanf(cl->buffer, "%*d %as", &buffer) != 1)
    {
       syslog(LOG_ERR, _("Got bad CHALLENGE from %s (%s)"), cl->name, cl->hostname);
       return -1;
    }

  /* Check if the length of the challenge is all right */

  if(strlen(buffer) != CHAL_LENGTH*2)
    {
      syslog(LOG_ERR, _("Intruder: wrong challenge length from %s (%s)"), cl->name, cl->hostname);
      free(buffer);
      return -1;
    }

  /* Allocate buffers for the challenge */

  if(!cl->mychallenge)
    cl->mychallenge = xmalloc(CHAL_LENGTH);

  /* Convert the challenge from hexadecimal back to binary */

  hex2bin(buffer,cl->mychallenge,CHAL_LENGTH);
  free(buffer);
    
  /* Rest is done by send_chal_reply() */
cp
  return send_chal_reply(cl);
}

int send_chal_reply(conn_list_t *cl)
{
  char hash[SHA_DIGEST_LENGTH*2+1];
cp
  if(!cl->mychallenge)
    {
      syslog(LOG_ERR, _("Trying to send CHAL_REPLY to %s (%s) without a valid CHALLENGE"), cl->name, cl->hostname);
      return -1;
    }
     
  /* Calculate the hash from the challenge we received */

  SHA1(cl->mychallenge, CHAL_LENGTH, hash);

  /* Convert the hash to a hexadecimal formatted string */

  bin2hex(hash,hash,SHA_DIGEST_LENGTH);
  hash[SHA_DIGEST_LENGTH*2] = '\0';

  /* Send the reply */

  if(cl->status.outgoing)
    cl->allow_request = ID;
  else
    cl->allow_request = ACK;

cp
  return send_request(cl, "%d %s", CHAL_REPLY, hash);
}

int chal_reply_h(conn_list_t *cl)
{
  char *hishash;
  char myhash[SHA_DIGEST_LENGTH];
cp
  if(sscanf(cl->buffer, "%*d %as", &hishash) != 2)
    {
       syslog(LOG_ERR, _("Got bad CHAL_REPLY from %s (%s)"), cl->name, cl->hostname);
       free(hishash);
       return -1;
    }

  /* Check if the length of the hash is all right */

  if(strlen(hishash) != SHA_DIGEST_LENGTH*2)
    {
      syslog(LOG_ERR, _("Intruder: wrong challenge reply length from %s (%s)"), cl->name, cl->hostname);
      free(hishash);
      return -1;
    }

  /* Convert the hash to binary format */

  hex2bin(hishash, hishash, SHA_DIGEST_LENGTH);

  /* Calculate the hash from the challenge we sent */

  SHA1(cl->hischallenge, CHAL_LENGTH, myhash);

  /* Verify the incoming hash with the calculated hash */

  if(!memcmp(hishash, myhash, SHA_DIGEST_LENGTH))
    {
      syslog(LOG_ERR, _("Intruder: wrong challenge reply from %s (%s)"), cl->name, cl->hostname);
      free(hishash);
      return -1;
    }

  free(hishash);

  /* Identity has now been positively verified.
     If we are accepting this new connection, then send our identity,
     if we are making this connecting, acknowledge.
   */
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
  conn_list_t *old;
cp
  /* Okay, before we active the connection, we check if there is another entry
     in the connection list with the same name. If so, it presumably is an
     old connection that has timed out but we don't know it yet.
   */

  while((old = lookup_id(cl->name)))
    {
      if(debug_lvl > DEBUG_CONNECTIONS)
        syslog(LOG_NOTICE, _("Removing old entry for %s at %s in favour of new connection from %s"),
        cl->name, old->hostname, cl->hostname);
      old->status.active = 0;
      terminate_connection(old);
    }

  /* Activate this connection */

  cl->allow_request = ALL;
  cl->status.active = 1;

  if(debug_lvl > DEBUG_CONNECTIONS)
    syslog(LOG_NOTICE, _("Connection with %s (%s) activated"), cl->name, cl->hostname);

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
  int x;
  char *netstr;
cp
  x = send_request(cl, "%d %s %s", ADD_SUBNET,
                      other->name, netstr = net2str(subnet));
  free(netstr);
cp
  return x;
}

int add_subnet_h(conn_list_t *cl)
{
  char *subnetstr;
  char *name;
  conn_list_t *owner;
  subnet_t *subnet, *old;
cp
  if(sscanf(cl->buffer, "%*d %as %as", &name, &subnetstr) != 3)
    {
      syslog(LOG_ERR, _("Got bad ADD_SUBNET from %s (%s)"), cl->name, cl->hostname);
      free(name); free(subnetstr);
      return -1;
    }

  /* Check if owner name is a valid */

  if(!check_id(name))
    {
      syslog(LOG_ERR, _("Got bad ADD_SUBNET from %s (%s): invalid identity name"), cl->name, cl->hostname);
      free(name); free(subnetstr);
      return -1;
    }

  /* Check if subnet string is valid */

  if((subnet = str2net(subnetstr)) == -1)
    {
      syslog(LOG_ERR, _("Got bad ADD_SUBNET from %s (%s): invalid subnet string"), cl->name, cl->hostname);
      free(name); free(subnetstr);
      return -1;
    }

  free(subnetstr);
  
  /* Check if somebody tries to add a subnet of ourself */

  if(!strcmp(name, myself->name))
    {
      syslog(LOG_ERR, _("Warning: got ADD_SUBNET from %s (%s) for ourself, restarting"),
             cl->name, cl->hostname);
      free(name);
      sighup = 1;
      return 0;
    }

  /* Check if the owner of the new subnet is in the connection list */

  if(!(owner = lookup_id(name))
    {
      syslog(LOG_ERR, _("Got ADD_SUBNET for %s from %s (%s) which is not in our connection list"),
             name, cl->name, cl->hostname);
      free(name);
      return -1;
    }

  /* If everything is correct, add the subnet to the list of the owner */
cp
  return subnet_add(owner, subnet);
}

int send_del_subnet(conn_list_t *cl, conn_list_t *other, subnet_t *subnet)
{
cp
  return send_request(cl, "%d %s %s", DEL_SUBNET, other->name, net2str(subnet));
}

int del_subnet_h(conn_list_t *cl)
{
  char *subnetstr;
  char *name;
  conn_list_t *owner;
  subnet_t *subnet, *old;
cp
  if(sscanf(cl->buffer, "%*d %as %as", &name, &subnetstr) != 3)
    {
      syslog(LOG_ERR, _("Got bad DEL_SUBNET from %s (%s)"), cl->name, cl->hostname);
      free(name); free(subnetstr);
      return -1;
    }

  /* Check if owner name is a valid */

  if(!check_id(name))
    {
      syslog(LOG_ERR, _("Got bad DEL_SUBNET from %s (%s): invalid identity name"), cl->name, cl->hostname);
      free(name); free(subnetstr);
      return -1;
    }

  /* Check if subnet string is valid */

  if((subnet = str2net(subnetstr)) == -1)
    {
      syslog(LOG_ERR, _("Got bad DEL_SUBNET from %s (%s): invalid subnet string"), cl->name, cl->hostname);
      free(name); free(subnetstr);
      return -1;
    }

  free(subnetstr);
  
  /* Check if somebody tries to add a subnet of ourself */

  if(!strcmp(name, myself->name))
    {
      syslog(LOG_ERR, _("Warning: got DEL_SUBNET from %s (%s) for ourself, restarting"),
             cl->name, cl->hostname);
      free(name);
      sighup = 1;
      return 0;
    }

  /* Check if the owner of the new subnet is in the connection list */

  if(!(owner = lookup_id(name))
    {
      syslog(LOG_ERR, _("Got DEL_SUBNET for %s from %s (%s) which is not in our connection list"),
             name, cl->name, cl->hostname);
      free(name);
      return -1;
    }

  /* If everything is correct, add the subnet to the list of the owner */
cp
  return subnet_del(owner, subnet);
}

/* New and closed connections notification */

int send_add_host(conn_list_t *cl, conn_list_t *other)
{
cp
  return send_request(cl, "%d %s %s %lx:%d %lx", ADD_HOST,
                      myself->name, other->name, other->real_ip, other->port, other->options);
}

int add_host_h(conn_list_t *cl)
{
  char *sender;
  conn_list_t *old, *new, *hisuplink;
cp
  new = new_conn_list();

  if(sscanf(cl->buffer, "%*d %as %as %lx:%d %lx", &sender, &new->name, &new->address, &new->port, &new->options) != 5)
    {
       syslog(LOG_ERR, _("Got bad ADD_HOST from %s (%s)"), cl->name, cl->hostname);
       return -1;
    }

  /* Check if identity is a valid name */

  if(!check_id(new->name) || !check_id(sender))
    {
      syslog(LOG_ERR, _("Got bad ADD_HOST from %s (%s): invalid identity name"), cl->name, cl->hostname);
      free(sender);
      return -1;
    }

  /* Check if somebody tries to add ourself */

  if(!strcmp(new->name, myself->name))
    {
      syslog(LOG_ERR, _("Warning: got ADD_HOST from %s (%s) for ourself, restarting"), cl->name, cl->hostname);
      sighup = 1;
      free(sender);
      return 0;
    }

  /* We got an ADD_HOST from ourself!? */

  if(!strcmp(sender, myself->name))
    {
      syslog(LOG_ERR, _("Warning: got ADD_HOST from %s (%s) from ourself, restarting"), cl->name, cl->hostname);
      sighup = 1;
      free(sender);
      return 0;
    }

  /* Lookup his uplink */

  if(!(new->hisuplink = lookup_id(sender))
    {
      syslog(LOG_ERR, _("Got ADD_HOST from %s (%s) with origin %s which is not in our connection list"),
             sender, cl->name, cl->hostname);
      free(sender);
      return -1;
    }
    
  free(sender);

  /* Fill in more of the new conn_list structure */

  new->hostname = hostlookup(htonl(new->real_ip));

  /* Check if the new host already exists in the connnection list */

  if((old = lookup_id(new->name)))
    {
      if((new->real_ip == old->real_ip) && (new->port == old->port))
        {
          if(debug_lvl > DEBUG_CONNECTIONS)
            syslog(LOG_NOTICE, _("Got duplicate ADD_HOST for %s (%s) from %s (%s)"),
                   old->name, old->hostname, new->name, new->hostname);
          return 0;
        }
      else
        {
          if(debug_lvl > DEBUG_CONNECTIONS)
            syslog(LOG_NOTICE, _("Removing old entry for %s (%s)"),
                   old->name, old->hostname);
          old->status.active = 0;
          terminate_connection(old);
        }
    }

  /* Fill in rest of conn_list structure */

  new->myuplink = cl;
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
  return send_request(cl, "%d %s %s %lx:%d %lx", DEL_HOST,
                      myself->name, other->name, other->real_ip, other->port, other->options);
}

int del_host_h(conn_list_t *cl)
{
  char *name;
  char *sender;
  ip_t address;
  port_t port;
  int options;
  conn_list_t *old, *hisuplink;

cp
  if(sscanf(cl->buffer, "%*d %as %as %lx:%d %lx", &sender, &name, &address, &port, &options) != 5)
    {
      syslog(LOG_ERR, _("Got bad DEL_HOST from %s (%s)"),
             cl->name, cl->hostname);
      return -1;
    }

  /* Check if identity is a valid name */

  if(!check_id(name) || !check_id(sender))
    {
      syslog(LOG_ERR, _("Got bad DEL_HOST from %s (%s): invalid identity name"), cl->name, cl->hostname);
      free(name); free(sender);
      return -1;
    }

  /* Check if somebody tries to delete ourself */

  if(!strcmp(name, myself->name))
    {
      syslog(LOG_ERR, _("Warning: got DEL_HOST from %s (%s) for ourself, restarting"),
             cl->name, cl->hostname);
      free(name); free(sender);
      sighup = 1;
      return 0;
    }

  /* We got an ADD_HOST from ourself!? */

  if(!strcmp(sender, myself->name))
    {
      syslog(LOG_ERR, _("Warning: got DEL_HOST from %s (%s) from ourself, restarting"), cl->name, cl->hostname);
      sighup = 1;
      free(name); free(sender);
      return 0;
    }

  /* Lookup his uplink */

  if(!(hisuplink = lookup_id(sender))
    {
      syslog(LOG_ERR, _("Got DEL_HOST from %s (%s) with origin %s which is not in our connection list"),
             cl->name, cl->hostname, sender);
      free(name); free(sender);
      return -1;
    }
    
  free(sender);

  /* Check if the new host already exists in the connnection list */

  if(!(old = lookup_id(name)))
    {
      syslog(LOG_ERR, _("Got DEL_HOST from %s (%s) for %s which is not in our connection list"),
             name, cl->name, cl->hostname);
      free(name);
      return -1;
    }
  
  /* Check if the rest matches */
  
  if(address!=old->address || port!=old->port || options!=old->options || hisuplink!=old->hisuplink || cl!=old->myuplink)
    {
      syslog(LOG_WARNING, _("Got DEL_HOST from %s (%s) for %s which doesn't match"), cl->name, cl->hostname, old->name);
      return 0;
    }

  /* Ok, since EVERYTHING seems to check out all right, delete it */

  old->status.termreq = 1;
  old->status.active = 0;

  terminate_connection(old);
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
       syslog(LOG_ERR, _("Got bad STATUS from %s (%s)"),
              cl->name, cl->hostname);
       return -1;
    }

  if(debug_lvl > DEBUG_STATUS)
    {
      syslog(LOG_NOTICE, _("Status message from %s (%s): %s: %s"),
             cl->name, cl->hostname, status_text[statusno], statusstring);
    }

cp
  free(statusstring);
  return 0;
}

int send_error(conn_list_t *cl, int errno, char *errstring)
{
cp
  if(!errstring)
    errstring = strerror(errno);
  return send_request(cl, "%d %d %s", ERROR, errno, errstring);
}

int error_h(conn_list_t *cl)
{
  int errno;
  char *errorstring;
cp
  if(sscanf(cl->buffer, "%*d %d %as", &errno, &errorstring) != 2)
    {
       syslog(LOG_ERR, _("Got bad error from %s (%s)"),
              cl->name, cl->hostname);
       return -1;
    }

  if(debug_lvl > DEBUG_error)
    {
      syslog(LOG_NOTICE, _("Error message from %s (%s): %s: %s"),
             cl->name, cl->hostname, strerror(errno), errorstring);
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
        send_request(p, "%d %s", KEY_CHANGED,
                     from->name);
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
      syslog(LOG_ERR, _("Got bad KEY_CHANGED from %s (%s)"),
             cl->name, cl->hostname);
      return -1;
    }

  if(!(from = lookup_id(from_id)))
    {
      syslog(LOG_ERR, _("Got KEY_CHANGED from %s (%s) origin %s which does not exist in our connection list"),
             cl->name, cl->hostname, from_id);
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
  return send_request(to->nexthop, "%d %s %s", REQ_KEY,
                      from->name, to->name);
}

int req_key_h(conn_list_t *cl)
{
  char *from_id, *to_id;
  conn_list_t *from, *to;
cp
  if(sscanf(cl->buffer, "%*d %as %as", &from_id, &to_id) != 2)
    {
       syslog(LOG_ERR, _("Got bad REQ_KEY from %s (%s)"),
              cl->name, cl->hostname);
       return -1;
    }

  if(!(from = lookup_id(from_id)))
    {
      syslog(LOG_ERR, _("Got REQ_KEY from %s (%s) origin %s which does not exist in our connection list"),
             cl->name, cl->hostname, from_id);
      free(from_id); free(to_id);
      return -1;
    }

  /* Check if this key request is for us */

  if(!strcmp(to_id, myself->name))
    {
      send_ans_key(myself, from, myself->datakey->key);
    }
  else
    {
      if(!(to = lookup_id(to_id)))
        {
          syslog(LOG_ERR, _("Got REQ_KEY from %s (%s) destination %s which does not exist in our connection list"),
                 cl->name, cl->hostname, to_id);
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
  return send_request(to->nexthop, "%d %s %s %s", ANS_KEY,
                      from->name, to->name, datakey);
}

int ans_key_h(conn_list_t *cl)
{
  char *from_id, *to_id, *datakey;
  int keylength;
  conn_list_t *from, *to;
cp
  if(sscanf(cl->buffer, "%*d %as %as %as", &from_id, &to_id, &datakey) != 3)
    {
       syslog(LOG_ERR, _("Got bad ANS_KEY from %s (%s)"),
              cl->name, cl->hostname);
       return -1;
    }

  if(!(from = lookup_id(from_id)))
    {
      syslog(LOG_ERR, _("Got ANS_KEY from %s (%s) origin %s which does not exist in our connection list"),
             cl->name, cl->hostname, from_id);
      free(from_id); free(to_id); free(datakey);
      return -1;
    }

  /* Check if this key request is for us */

  if(!strcmp(to_id, myself->name))
    {
      /* It is for us, convert it to binary and set the key with it. */

      keylength = strlen(datakey);

      if((keylength%2) || (keylength <= 0))
        {
          syslog(LOG_ERR, _("Got bad ANS_KEY from %s (%s) origin %s: invalid key"),
                 cl->name, cl->hostname, from->name);
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
          syslog(LOG_ERR, _("Got ANS_KEY from %s (%s) destination %s which does not exist in our connection list"),
                 cl->name, cl->hostname, to_id);
          free(from_id); free(to_id); free(datakey);
          return -1;
        }
      send_ans_key(from, to, datakey);
    }

  free(from_id); free(to_id); free(datakey);
cp
  return 0;
}

/* Jumptable for the request handlers */

int (*request_handlers[])(conn_list_t*) = {
  id_h, challenge_h, chal_reply_h, ack_h,
  status_h, error_h, termreq_h,
  ping_h, pong_h,
  add_host_h, del_host_h,
  add_subnet_h, del_subnet_h,
  key_changed_h, req_key_h, ans_key_h,
};

/* Request names */

char (*request_name[]) = {
  "ID", "CHALLENGE", "CHAL_REPLY", "ACK",
  "STATUS", "ERROR", "TERMREQ",
  "PING", "PONG",
  "ADD_HOST", "DEL_HOST",
  "ADD_SUBNET", "DEL_SUBNET",
  "KEY_CHANGED", "REQ_KEY", "ANS_KEY",
};
