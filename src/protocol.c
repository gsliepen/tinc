/*
    protocol.c -- handle the meta-protocol
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

    $Id: protocol.c,v 1.28.4.97 2001/07/01 21:42:13 guus Exp $
*/

#include "config.h"

#include <sys/types.h>

#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <sys/socket.h>
#include <unistd.h>
#include <stdio.h>
#include <stdarg.h>
#include <errno.h>

#include <utils.h>
#include <xalloc.h>
#include <avl_tree.h>
#include <list.h>

#include <netinet/in.h>

#ifdef HAVE_OPENSSL_SHA_H
# include <openssl/sha.h>
#else
# include <sha.h>
#endif

#ifdef HAVE_OPENSSL_RAND_H
# include <openssl/rand.h>
#else
# include <rand.h>
#endif

#ifdef HAVE_OPENSSL_EVP_H
# include <openssl/evp.h>
#else
# include <evp.h>
#endif


#include "conf.h"
#include "net.h"
#include "netutl.h"
#include "protocol.h"
#include "meta.h"
#include "connection.h"

#include "system.h"

int mykeyused = 0;

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

int send_request(connection_t *cl, const char *format, ...)
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
  request = va_arg(args, int);
  va_end(args);

  if(len < 0 || len > MAXBUFSIZE-1)
    {
      syslog(LOG_ERR, _("Output buffer overflow while sending %s to %s (%s)"), request_name[request], cl->name, cl->hostname);
      return -1;
    }

  if(debug_lvl >= DEBUG_PROTOCOL)
    {
      if(debug_lvl >= DEBUG_META)
        syslog(LOG_DEBUG, _("Sending %s to %s (%s): %s"), request_name[request], cl->name, cl->hostname, buffer);
      else
        syslog(LOG_DEBUG, _("Sending %s to %s (%s)"), request_name[request], cl->name, cl->hostname);
    }

  buffer[len++] = '\n';
cp
  return send_meta(cl, buffer, len);
}

int receive_request(connection_t *cl)
{
  int request;
cp
  if(sscanf(cl->buffer, "%d", &request) == 1)
    {
      if((request < 0) || (request >= LAST) || (request_handlers[request] == NULL))
        {
          if(debug_lvl >= DEBUG_META)
            syslog(LOG_DEBUG, _("Unknown request from %s (%s): %s"),
	           cl->name, cl->hostname, cl->buffer);
          else
            syslog(LOG_ERR, _("Unknown request from %s (%s)"),
                   cl->name, cl->hostname);
                   
          return -1;
        }
      else
        {
          if(debug_lvl >= DEBUG_PROTOCOL)
            {
              if(debug_lvl >= DEBUG_META)
                syslog(LOG_DEBUG, _("Got %s from %s (%s): %s"),
	               request_name[request], cl->name, cl->hostname, cl->buffer);
              else
                syslog(LOG_DEBUG, _("Got %s from %s (%s)"),
		       request_name[request], cl->name, cl->hostname);
            }
	}

      if((cl->allow_request != ALL) && (cl->allow_request != request))
        {
          syslog(LOG_ERR, _("Unauthorized request from %s (%s)"), cl->name, cl->hostname);
          return -1;
        }

      if(request_handlers[request](cl))
	/* Something went wrong. Probably scriptkiddies. Terminate. */
        {
          syslog(LOG_ERR, _("Error while processing %s from %s (%s)"),
		 request_name[request], cl->name, cl->hostname);
          return -1;
        }
    }
  else
    {
      syslog(LOG_ERR, _("Bogus data received from %s (%s)"),
	     cl->name, cl->hostname);
      return -1;
    }
cp
  return 0;
}

/* The authentication protocol is described in detail in doc/SECURITY2,
   the rest will be described in doc/PROTOCOL. */

int send_id(connection_t *cl)
{
cp
  return send_request(cl, "%d %s %d %lx %hd", ID, myself->name, myself->protocol_version, myself->options, myself->port);
}

int id_h(connection_t *cl)
{
  connection_t *old;
  unsigned short int port;
  char name[MAX_STRING_SIZE];
  avl_node_t *node;
cp
  if(sscanf(cl->buffer, "%*d "MAX_STRING" %d %lx %hd", name, &cl->protocol_version, &cl->options, &port) != 4)
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

  if(check_id(name))
    {
      syslog(LOG_ERR, _("Peer %s uses invalid identity name"), cl->hostname);
      return -1;
    }
  
  /* Copy string to cl */
  
  if(cl->name)
    free(cl->name);
    
  cl->name = xstrdup(name);

  /* Load information about peer */

  if(read_host_config(cl))
    {
      syslog(LOG_ERR, _("Peer %s had unknown identity (%s)"), cl->hostname, cl->name);
      return -1;
    }

  /* First check if the host is already in our
     connection list. If so, we are probably making a loop, which
     is not desirable.
   */

  if((old = lookup_id(cl->name)))
    {
      if(debug_lvl >= DEBUG_CONNECTIONS)
        syslog(LOG_NOTICE, _("%s (%s) is already in our connection list"), cl->name, cl->hostname);
      if(cl->status.outgoing)
        {
          cl->status.outgoing = 0;
          old->status.outgoing = 1;
        }
      terminate_connection(cl);
      return 0;
    }
    
  /* Now we can add the name to the id tree */
  
  id_add(cl);

  /* And uhr... cl->port just changed so we have to unlink it from the connection tree and re-insert... */
  
  node = avl_unlink(connection_tree, cl);
  cl->port = port;
  if(!avl_insert_node(connection_tree, node))
    {
      old = avl_search_node(connection_tree, node)->data;
      syslog(LOG_ERR, _("%s is listening on %s:%hd, which is already in use by %s!"),
             cl->name, cl->hostname, cl->port, old->name);
      return -1;
    }
    
  /* Read in the public key, so that we can send a metakey */

  if(read_rsa_public_key(cl))
    return -1;

  cl->allow_request = METAKEY;
cp
  return send_metakey(cl);
}

int ack_h(connection_t *cl)
{
  config_t const *cfg;
  connection_t *old, *p;
  subnet_t *subnet;
  avl_node_t *node, *node2;
cp
  /* Okay, before we active the connection, we check if there is another entry
     in the connection list with the same name. If so, it presumably is an
     old connection that has timed out but we don't know it yet.
   */

  while((old = lookup_id(cl->name)))
    {
      if(debug_lvl >= DEBUG_CONNECTIONS)
        syslog(LOG_NOTICE, _("Removing old entry for %s at %s in favour of new connection from %s"),
        cl->name, old->hostname, cl->hostname);

      terminate_connection(old);
    }

  /* Activate this connection */

  cl->allow_request = ALL;
  cl->status.active = 1;
  cl->nexthop = cl;
  cl->cipher_pkttype = EVP_bf_cbc();
  cl->cipher_pktkeylength = cl->cipher_pkttype->key_len + cl->cipher_pkttype->iv_len;

  if(debug_lvl >= DEBUG_CONNECTIONS)
    syslog(LOG_NOTICE, _("Connection with %s (%s) activated"), cl->name, cl->hostname);

  if(cl->status.outgoing)
    seconds_till_retry = 5;	/* Reset retry timeout */
cp
  /* Check some options */
  
  if((cfg = get_config_val(cl->config, config_indirectdata)))
    {
      if(cfg->data.val == stupid_true)
        cl->options |= OPTION_INDIRECT;
    }

  if((cfg = get_config_val(cl->config, config_tcponly)))
    {
      if(cfg->data.val == stupid_true)
        cl->options |= OPTION_TCPONLY;
    }

  /* Send him our subnets */
  
  for(node = myself->subnet_tree->head; node; node = node->next)
    {
      subnet = (subnet_t *)node->data;
      send_add_subnet(cl, subnet);
    }

  /* And send him all the hosts and their subnets we know... */
  
  for(node = connection_tree->head; node; node = node->next)
    {
      p = (connection_t *)node->data;
      
      if(p != cl && p->status.active)
        {
          /* Notify others of this connection */

          if(p->status.meta)
            send_add_host(p, cl);

          /* Notify new connection of everything we know */

          send_add_host(cl, p);

          for(node2 = p->subnet_tree->head; node2; node2 = node2->next)
            {
              subnet = (subnet_t *)node2->data;
              send_add_subnet(cl, subnet);
            }
        }
    }  
cp
  return 0;
}

int send_challenge(connection_t *cl)
{
  char *buffer;
  int len, x;
cp
  /* CHECKME: what is most reasonable value for len? */

  len = RSA_size(cl->rsa_key);

  /* Allocate buffers for the challenge */

  buffer = xmalloc(len*2+1);

  if(cl->hischallenge)
    free(cl->hischallenge);
    
  cl->hischallenge = xmalloc(len);
cp
  /* Copy random data to the buffer */

  RAND_bytes(cl->hischallenge, len);

cp
  /* Convert to hex */

  bin2hex(cl->hischallenge, buffer, len);
  buffer[len*2] = '\0';

cp
  /* Send the challenge */

  x = send_request(cl, "%d %s", CHALLENGE, buffer);
  free(buffer);
cp
  return x;
}

int challenge_h(connection_t *cl)
{
  char buffer[MAX_STRING_SIZE];
  int len;
cp
  if(sscanf(cl->buffer, "%*d "MAX_STRING, buffer) != 1)
    {
       syslog(LOG_ERR, _("Got bad CHALLENGE from %s (%s)"), cl->name, cl->hostname);
       return -1;
    }

  len = RSA_size(myself->rsa_key);

  /* Check if the length of the challenge is all right */

  if(strlen(buffer) != len*2)
    {
      syslog(LOG_ERR, _("Intruder: wrong challenge length from %s (%s)"), cl->name, cl->hostname);
      return -1;
    }

  /* Allocate buffers for the challenge */

  if(!cl->mychallenge)
    cl->mychallenge = xmalloc(len);

  /* Convert the challenge from hexadecimal back to binary */

  hex2bin(buffer,cl->mychallenge,len);

  cl->allow_request = CHAL_REPLY;

  /* Rest is done by send_chal_reply() */
cp
  return send_chal_reply(cl);
}

int send_chal_reply(connection_t *cl)
{
  char hash[SHA_DIGEST_LENGTH*2+1];
cp
  if(!cl->mychallenge)
    {
      syslog(LOG_ERR, _("Trying to send CHAL_REPLY to %s (%s) without a valid CHALLENGE"), cl->name, cl->hostname);
      return -1;
    }
     
  /* Calculate the hash from the challenge we received */

  SHA1(cl->mychallenge, RSA_size(myself->rsa_key), hash);

  /* Convert the hash to a hexadecimal formatted string */

  bin2hex(hash,hash,SHA_DIGEST_LENGTH);
  hash[SHA_DIGEST_LENGTH*2] = '\0';

  /* Send the reply */

cp
  return send_request(cl, "%d %s", CHAL_REPLY, hash);
}

int chal_reply_h(connection_t *cl)
{
  char hishash[MAX_STRING_SIZE];
  char myhash[SHA_DIGEST_LENGTH];
cp
  if(sscanf(cl->buffer, "%*d "MAX_STRING, hishash) != 1)
    {
       syslog(LOG_ERR, _("Got bad CHAL_REPLY from %s (%s)"), cl->name, cl->hostname);
       return -1;
    }

  /* Check if the length of the hash is all right */

  if(strlen(hishash) != SHA_DIGEST_LENGTH*2)
    {
      syslog(LOG_ERR, _("Intruder: wrong challenge reply length from %s (%s)"), cl->name, cl->hostname);
      return -1;
    }

  /* Convert the hash to binary format */

  hex2bin(hishash, hishash, SHA_DIGEST_LENGTH);

  /* Calculate the hash from the challenge we sent */

  SHA1(cl->hischallenge, RSA_size(cl->rsa_key), myhash);

  /* Verify the incoming hash with the calculated hash */

  if(memcmp(hishash, myhash, SHA_DIGEST_LENGTH))
    {
      syslog(LOG_ERR, _("Intruder: wrong challenge reply from %s (%s)"), cl->name, cl->hostname);
      if(debug_lvl >= DEBUG_SCARY_THINGS)
        {
          bin2hex(myhash, hishash, SHA_DIGEST_LENGTH);
          hishash[SHA_DIGEST_LENGTH*2] = '\0';
          syslog(LOG_DEBUG, _("Expected challenge reply: %s"), hishash);
        }
      return -1;
    }

  /* Identity has now been positively verified.
     ack_h() handles the rest from now on.
   */
cp
  return ack_h(cl);
}

int send_metakey(connection_t *cl)
{
  char *buffer;
  int len, x;
cp
  len = RSA_size(cl->rsa_key);

  /* Allocate buffers for the meta key */

  buffer = xmalloc(len*2+1);

  if(!cl->cipher_outkey)
    cl->cipher_outkey = xmalloc(len);
    
  if(!cl->cipher_outctx)
    cl->cipher_outctx = xmalloc(sizeof(*cl->cipher_outctx));
cp
  /* Copy random data to the buffer */

  RAND_bytes(cl->cipher_outkey, len);

  /* The message we send must be smaller than the modulus of the RSA key.
     By definition, for a key of k bits, the following formula holds:
     
       2^(k-1) <= modulus < 2^(k)
     
     Where ^ means "to the power of", not "xor".
     This means that to be sure, we must choose our message < 2^(k-1).
     This can be done by setting the most significant bit to zero.
  */
  
  cl->cipher_outkey[0] &= 0x7F;
  
  if(debug_lvl >= DEBUG_SCARY_THINGS)
    {
      bin2hex(cl->cipher_outkey, buffer, len);
      buffer[len*2] = '\0';
      syslog(LOG_DEBUG, _("Generated random meta key (unencrypted): %s"), buffer);
    }

  /* Encrypt the random data
  
     We do not use one of the PKCS padding schemes here.
     This is allowed, because we encrypt a totally random string
     with a length equal to that of the modulus of the RSA key.
  */
  
  if(RSA_public_encrypt(len, cl->cipher_outkey, buffer, cl->rsa_key, RSA_NO_PADDING) != len)
    {
      syslog(LOG_ERR, _("Error during encryption of meta key for %s (%s)"), cl->name, cl->hostname);
      free(buffer);
      return -1;
    }
cp
  /* Convert the encrypted random data to a hexadecimal formatted string */

  bin2hex(buffer, buffer, len);
  buffer[len*2] = '\0';

  /* Send the meta key */

  x = send_request(cl, "%d %s", METAKEY, buffer);
  free(buffer);

  /* Further outgoing requests are encrypted with the key we just generated */

  EVP_EncryptInit(cl->cipher_outctx, EVP_bf_cfb(),
                  cl->cipher_outkey + len - EVP_bf_cfb()->key_len,
                  cl->cipher_outkey + len - EVP_bf_cfb()->key_len - EVP_bf_cfb()->iv_len);

  cl->status.encryptout = 1;
cp
  return x;
}

int metakey_h(connection_t *cl)
{
  char buffer[MAX_STRING_SIZE];
  int len;
cp
  if(sscanf(cl->buffer, "%*d "MAX_STRING, buffer) != 1)
    {
       syslog(LOG_ERR, _("Got bad METAKEY from %s (%s)"), cl->name, cl->hostname);
       return -1;
    }

  len = RSA_size(myself->rsa_key);

  /* Check if the length of the meta key is all right */

  if(strlen(buffer) != len*2)
    {
      syslog(LOG_ERR, _("Intruder: wrong meta key length from %s (%s)"), cl->name, cl->hostname);
      return -1;
    }

  /* Allocate buffers for the meta key */

  if(!cl->cipher_inkey)
    cl->cipher_inkey = xmalloc(len);

  if(!cl->cipher_inctx)
    cl->cipher_inctx = xmalloc(sizeof(*cl->cipher_inctx));

  /* Convert the challenge from hexadecimal back to binary */

  hex2bin(buffer,buffer,len);

  /* Decrypt the meta key */
  
  if(RSA_private_decrypt(len, buffer, cl->cipher_inkey, myself->rsa_key, RSA_NO_PADDING) != len)	/* See challenge() */
    {
      syslog(LOG_ERR, _("Error during encryption of meta key for %s (%s)"), cl->name, cl->hostname);
      return -1;
    }

  if(debug_lvl >= DEBUG_SCARY_THINGS)
    {
      bin2hex(cl->cipher_inkey, buffer, len);
      buffer[len*2] = '\0';
      syslog(LOG_DEBUG, _("Received random meta key (unencrypted): %s"), buffer);
    }

  /* All incoming requests will now be encrypted. */

  EVP_DecryptInit(cl->cipher_inctx, EVP_bf_cfb(),
                  cl->cipher_inkey + len - EVP_bf_cfb()->key_len,
                  cl->cipher_inkey + len - EVP_bf_cfb()->key_len - EVP_bf_cfb()->iv_len);
  
  cl->status.decryptin = 1;

  cl->allow_request = CHALLENGE;
cp
  return send_challenge(cl);
}

/* Address and subnet information exchange */

int send_add_subnet(connection_t *cl, subnet_t *subnet)
{
  int x;
  char *netstr;
  char *owner;
cp
  if((cl->options | myself->options | subnet->owner->options) & OPTION_INDIRECT)
    owner = myself->name;
  else
    owner = subnet->owner->name;

  x = send_request(cl, "%d %s %s", ADD_SUBNET,
                      owner, netstr = net2str(subnet));
  free(netstr);
cp
  return x;
}

int add_subnet_h(connection_t *cl)
{
  char subnetstr[MAX_STRING_SIZE];
  char name[MAX_STRING_SIZE];
  connection_t *owner, *p;
  subnet_t *subnet;
  avl_node_t *node;
cp
  if(sscanf(cl->buffer, "%*d "MAX_STRING" "MAX_STRING, name, subnetstr) != 2)
    {
      syslog(LOG_ERR, _("Got bad ADD_SUBNET from %s (%s)"), cl->name, cl->hostname);
      return -1;
    }

  /* Check if owner name is a valid */

  if(check_id(name))
    {
      syslog(LOG_ERR, _("Got bad ADD_SUBNET from %s (%s): invalid identity name"), cl->name, cl->hostname);
      return -1;
    }

  /* Check if subnet string is valid */

  if(!(subnet = str2net(subnetstr)))
    {
      syslog(LOG_ERR, _("Got bad ADD_SUBNET from %s (%s): invalid subnet string"), cl->name, cl->hostname);
      return -1;
    }

  /* Check if somebody tries to add a subnet of ourself */

  if(!strcmp(name, myself->name))
    {
      syslog(LOG_ERR, _("Warning: got ADD_SUBNET from %s (%s) for ourself, restarting"),
             cl->name, cl->hostname);
      sighup = 1;
      return 0;
    }

  /* Check if the owner of the new subnet is in the connection list */

  if(!(owner = lookup_id(name)))
    {
      syslog(LOG_ERR, _("Got ADD_SUBNET for %s from %s (%s) which is not in our connection list"),
             name, cl->name, cl->hostname);
      return -1;
    }

  /* If everything is correct, add the subnet to the list of the owner */

  subnet_add(owner, subnet);

  /* Tell the rest */
  
  for(node = connection_tree->head; node; node = node->next)
    {
      p = (connection_t *)node->data;
      if(p->status.meta && p->status.active && p!= cl)
        send_add_subnet(p, subnet);
    }
cp
  return 0;
}

int send_del_subnet(connection_t *cl, subnet_t *subnet)
{
  int x;
  char *netstr;
  char *owner;
cp
  if(cl->options & OPTION_INDIRECT)
    owner = myself->name;
  else
    owner = subnet->owner->name;

  x = send_request(cl, "%d %s %s", DEL_SUBNET, owner, netstr = net2str(subnet));
  free(netstr);
cp
  return x;
}

int del_subnet_h(connection_t *cl)
{
  char subnetstr[MAX_STRING_SIZE];
  char name[MAX_STRING_SIZE];
  connection_t *owner, *p;
  subnet_t *subnet;
  avl_node_t *node;
cp
  if(sscanf(cl->buffer, "%*d "MAX_STRING" "MAX_STRING, name, subnetstr) != 3)
    {
      syslog(LOG_ERR, _("Got bad DEL_SUBNET from %s (%s)"), cl->name, cl->hostname);
      return -1;
    }

  /* Check if owner name is a valid */

  if(check_id(name))
    {
      syslog(LOG_ERR, _("Got bad DEL_SUBNET from %s (%s): invalid identity name"), cl->name, cl->hostname);
      return -1;
    }

  /* Check if subnet string is valid */

  if(!(subnet = str2net(subnetstr)))
    {
      syslog(LOG_ERR, _("Got bad DEL_SUBNET from %s (%s): invalid subnet string"), cl->name, cl->hostname);
      return -1;
    }

  free(subnetstr);
  
  /* Check if somebody tries to add a subnet of ourself */

  if(!strcmp(name, myself->name))
    {
      syslog(LOG_ERR, _("Warning: got DEL_SUBNET from %s (%s) for ourself, restarting"),
             cl->name, cl->hostname);
      sighup = 1;
      return 0;
    }

  /* Check if the owner of the new subnet is in the connection list */

  if(!(owner = lookup_id(name)))
    {
      syslog(LOG_ERR, _("Got DEL_SUBNET for %s from %s (%s) which is not in our connection list"),
             name, cl->name, cl->hostname);
      return -1;
    }

  /* If everything is correct, delete the subnet from the list of the owner */

  subnet_del(subnet);

  /* Tell the rest */
  
  for(node = connection_tree->head; node; node = node->next)
    {
      p = (connection_t *)node->data;
      if(p->status.meta && p->status.active && p!= cl)
        send_del_subnet(p, subnet);
    }
cp
  return 0;
}

/* New and closed connections notification */

int send_add_host(connection_t *cl, connection_t *other)
{
cp
  if(!((cl->options | myself->options | other->options) & OPTION_INDIRECT))
    return send_request(cl, "%d %s %lx:%d %lx", ADD_HOST,
                      other->name, other->address, other->port, other->options);
  else
    return 0;
}

int add_host_h(connection_t *cl)
{
  connection_t *old, *new, *p;
  char name[MAX_STRING_SIZE];
  avl_node_t *node;
cp
  new = new_connection();

  if(sscanf(cl->buffer, "%*d "MAX_STRING" %lx:%hd %lx", name, &new->address, &new->port, &new->options) != 4)
    {
       syslog(LOG_ERR, _("Got bad ADD_HOST from %s (%s)"), cl->name, cl->hostname);
       return -1;
    }

  /* Check if identity is a valid name */

  if(check_id(name))
    {
      syslog(LOG_ERR, _("Got bad ADD_HOST from %s (%s): invalid identity name"), cl->name, cl->hostname);
      free_connection(new);
      return -1;
    }

  /* Check if somebody tries to add ourself */

  if(!strcmp(name, myself->name))
    {
      syslog(LOG_ERR, _("Warning: got ADD_HOST from %s (%s) for ourself, restarting"), cl->name, cl->hostname);
      sighup = 1;
      free_connection(new);
      return 0;
    }
    
  /* Fill in more of the new connection structure */

  new->hostname = hostlookup(htonl(new->address));

  /* Check if the new host already exists in the connnection list */

  if((old = lookup_id(name)))
    {
      if((new->address == old->address) && (new->port == old->port))
        {
          if(debug_lvl >= DEBUG_CONNECTIONS)
            syslog(LOG_NOTICE, _("Got duplicate ADD_HOST for %s (%s) from %s (%s)"),
                   old->name, old->hostname, name, new->hostname);
          free_connection(new);
          return 0;
        }
      else
        {
          if(debug_lvl >= DEBUG_CONNECTIONS)
            syslog(LOG_NOTICE, _("Removing old entry for %s (%s) in favour of new connection"),
                   old->name, old->hostname);

          terminate_connection(old);
        }
    }

  /* Hook it up into the connection */

  new->name = xstrdup(name);
  connection_add(new);
  id_add(new);

  /* Tell the rest about the new host */

  for(node = connection_tree->head; node; node = node->next)
    {
      p = (connection_t *)node->data;
      if(p->status.meta && p->status.active && p!=cl)
        send_add_host(p, new);
    }

  /* Fill in rest of connection structure */

  new->nexthop = cl;
  new->status.active = 1;
  new->cipher_pkttype = EVP_bf_cbc();
  new->cipher_pktkeylength = cl->cipher_pkttype->key_len + cl->cipher_pkttype->iv_len;
cp
  return 0;
}

int send_del_host(connection_t *cl, connection_t *other)
{
cp
  if(!((cl->options | myself->options) & OPTION_INDIRECT))
    return send_request(cl, "%d %s %lx:%d %lx", DEL_HOST,
                      other->name, other->address, other->port, other->options);
  else
    return 0;
}

int del_host_h(connection_t *cl)
{
  char name[MAX_STRING_SIZE];
  ipv4_t address;
  port_t port;
  long int options;
  connection_t *old, *p;
  avl_node_t *node;
cp
  if(sscanf(cl->buffer, "%*d "MAX_STRING" %lx:%hd %lx", name, &address, &port, &options) != 4)
    {
      syslog(LOG_ERR, _("Got bad DEL_HOST from %s (%s)"),
             cl->name, cl->hostname);
      return -1;
    }

  /* Check if identity is a valid name */

  if(check_id(name))
    {
      syslog(LOG_ERR, _("Got bad DEL_HOST from %s (%s): invalid identity name"), cl->name, cl->hostname);
      return -1;
    }

  /* Check if somebody tries to delete ourself */

  if(!strcmp(name, myself->name))
    {
      syslog(LOG_ERR, _("Warning: got DEL_HOST from %s (%s) for ourself, restarting"),
             cl->name, cl->hostname);
      sighup = 1;
      return 0;
    }

  /* Check if the new host already exists in the connnection list */

  if(!(old = lookup_id(name)))
    {
      syslog(LOG_ERR, _("Got DEL_HOST from %s (%s) for %s which is not in our connection list"),
             name, cl->name, cl->hostname);
      return -1;
    }
  
  /* Check if the rest matches */
  
  if(address!=old->address || port!=old->port || options!=old->options || cl!=old->nexthop)
    {
      syslog(LOG_WARNING, _("Got DEL_HOST from %s (%s) for %s which doesn't match"), cl->name, cl->hostname, old->name);
      return 0;
    }

  /* Ok, since EVERYTHING seems to check out all right, delete it */

  old->status.active = 0;
  terminate_connection(old);

  /* Tell the rest about the new host */

  for(node = connection_tree->head; node; node = node->next)
    {
      p = (connection_t *)node->data;
      if(p->status.meta && p->status.active && p!=cl)
        send_del_host(p, old);
    }
cp
  return 0;
}

/* Status and error notification routines */

int send_status(connection_t *cl, int statusno, char *statusstring)
{
cp
  if(!statusstring)
    statusstring = status_text[statusno];
cp
  return send_request(cl, "%d %d %s", STATUS, statusno, statusstring);
}

int status_h(connection_t *cl)
{
  int statusno;
  char statusstring[MAX_STRING_SIZE];
cp
  if(sscanf(cl->buffer, "%*d %d "MAX_STRING, &statusno, statusstring) != 2)
    {
       syslog(LOG_ERR, _("Got bad STATUS from %s (%s)"),
              cl->name, cl->hostname);
       return -1;
    }

  if(debug_lvl >= DEBUG_STATUS)
    {
      syslog(LOG_NOTICE, _("Status message from %s (%s): %s: %s"),
             cl->name, cl->hostname, status_text[statusno], statusstring);
    }

cp
  return 0;
}

int send_error(connection_t *cl, int err, char *errstring)
{
cp
  if(!errstring)
    errstring = strerror(err);
  return send_request(cl, "%d %d %s", ERROR, err, errstring);
}

int error_h(connection_t *cl)
{
  int err;
  char errorstring[MAX_STRING_SIZE];
cp
  if(sscanf(cl->buffer, "%*d %d "MAX_STRING, &err, errorstring) != 2)
    {
       syslog(LOG_ERR, _("Got bad ERROR from %s (%s)"),
              cl->name, cl->hostname);
       return -1;
    }

  if(debug_lvl >= DEBUG_ERROR)
    {
      syslog(LOG_NOTICE, _("Error message from %s (%s): %s: %s"),
             cl->name, cl->hostname, strerror(err), errorstring);
    }

  terminate_connection(cl);
cp
  return 0;
}

int send_termreq(connection_t *cl)
{
cp
  return send_request(cl, "%d", TERMREQ);
}

int termreq_h(connection_t *cl)
{
cp
  terminate_connection(cl);
cp
  return 0;
}

int send_ping(connection_t *cl)
{
  char salt[SALTLEN*2+1];
cp
  cl->status.pinged = 1;
  cl->last_ping_time = time(NULL);
  RAND_bytes(salt, SALTLEN);
  bin2hex(salt, salt, SALTLEN);
  salt[SALTLEN*2] = '\0';
cp
  return send_request(cl, "%d %s", PING, salt);
}

int ping_h(connection_t *cl)
{
cp
  return send_pong(cl);
}

int send_pong(connection_t *cl)
{
  char salt[SALTLEN*2+1];
cp
  RAND_bytes(salt, SALTLEN);
  bin2hex(salt, salt, SALTLEN);
  salt[SALTLEN*2] = '\0';
cp
  return send_request(cl, "%d %s", PONG, salt);
}

int pong_h(connection_t *cl)
{
cp
  cl->status.pinged = 0;
cp
  return 0;
}

/* Key exchange */

int send_key_changed(connection_t *from, connection_t *cl)
{
  connection_t *p;
  avl_node_t *node;
cp
  /* Only send this message if some other daemon requested our key previously.
     This reduces unnecessary key_changed broadcasts.
  */

  if(from==myself && !mykeyused)
    return 0;

  for(node = connection_tree->head; node; node = node->next)
    {
      p = (connection_t *)node->data;
      if(p != cl && p->status.meta && p->status.active)
        if(!(p->options & OPTION_INDIRECT) || from == myself)
          send_request(p, "%d %s", KEY_CHANGED, from->name);
    }
cp
  return 0;
}

int key_changed_h(connection_t *cl)
{
  char from_id[MAX_STRING_SIZE];
  connection_t *from;
cp
  if(sscanf(cl->buffer, "%*d "MAX_STRING, from_id) != 1)
    {
      syslog(LOG_ERR, _("Got bad KEY_CHANGED from %s (%s)"),
             cl->name, cl->hostname);
      return -1;
    }

  if(!(from = lookup_id(from_id)))
    {
      syslog(LOG_ERR, _("Got KEY_CHANGED from %s (%s) origin %s which does not exist in our connection list"),
             cl->name, cl->hostname, from_id);
      return -1;
    }

  from->status.validkey = 0;
  from->status.waitingforkey = 0;

  if(!(from->options | cl->options | myself->options) & OPTION_INDIRECT)
    send_key_changed(from, cl);
cp
  return 0;
}

int send_req_key(connection_t *from, connection_t *to)
{
cp
  return send_request(to->nexthop, "%d %s %s", REQ_KEY,
                      from->name, to->name);
}

int req_key_h(connection_t *cl)
{
  char from_id[MAX_STRING_SIZE];
  char to_id[MAX_STRING_SIZE];
  connection_t *from, *to;
  char pktkey[129];
cp
  if(sscanf(cl->buffer, "%*d "MAX_STRING" "MAX_STRING, from_id, to_id) != 2)
    {
       syslog(LOG_ERR, _("Got bad REQ_KEY from %s (%s)"),
              cl->name, cl->hostname);
       return -1;
    }

  if(!(from = lookup_id(from_id)))
    {
      syslog(LOG_ERR, _("Got REQ_KEY from %s (%s) origin %s which does not exist in our connection list"),
             cl->name, cl->hostname, from_id);
      return -1;
    }

  /* Check if this key request is for us */

  if(!strcmp(to_id, myself->name))	/* Yes, send our own key back */
    {
      bin2hex(myself->cipher_pktkey, pktkey, myself->cipher_pktkeylength);
      pktkey[myself->cipher_pktkeylength*2] = '\0';
      send_ans_key(myself, from, pktkey);
      mykeyused = 1;
    }
  else
    {
      if(!(to = lookup_id(to_id)))
        {
          syslog(LOG_ERR, _("Got REQ_KEY from %s (%s) destination %s which does not exist in our connection list"),
                 cl->name, cl->hostname, to_id);
          return -1;
        }
        
      if(to->status.validkey)	/* Proxy keys */
        {
          bin2hex(to->cipher_pktkey, pktkey, to->cipher_pktkeylength);
          pktkey[to->cipher_pktkeylength*2] = '\0';
          send_ans_key(to, from, pktkey);
        }
      else
        send_req_key(from, to);
    }

cp
  return 0;
}

int send_ans_key(connection_t *from, connection_t *to, char *pktkey)
{
cp
  return send_request(to->nexthop, "%d %s %s %s", ANS_KEY,
                      from->name, to->name, pktkey);
}

int ans_key_h(connection_t *cl)
{
  char from_id[MAX_STRING_SIZE];
  char to_id[MAX_STRING_SIZE];
  char pktkey[MAX_STRING_SIZE];
  int keylength;
  connection_t *from, *to;
cp
  if(sscanf(cl->buffer, "%*d "MAX_STRING" "MAX_STRING" "MAX_STRING, from_id, to_id, pktkey) != 3)
    {
       syslog(LOG_ERR, _("Got bad ANS_KEY from %s (%s)"),
              cl->name, cl->hostname);
       return -1;
    }

  if(!(from = lookup_id(from_id)))
    {
      syslog(LOG_ERR, _("Got ANS_KEY from %s (%s) origin %s which does not exist in our connection list"),
             cl->name, cl->hostname, from_id);
      return -1;
    }

  /* Check correctness of packet key */

  keylength = strlen(pktkey);

  if(keylength != from->cipher_pktkeylength*2)
    {
      syslog(LOG_ERR, _("Got bad ANS_KEY from %s (%s) origin %s: invalid key length"),
             cl->name, cl->hostname, from->name);
      return -1;
    }

  /* Forward it if necessary */

  if(strcmp(to_id, myself->name))
    {
      if(!(to = lookup_id(to_id)))
        {
          syslog(LOG_ERR, _("Got ANS_KEY from %s (%s) destination %s which does not exist in our connection list"),
                 cl->name, cl->hostname, to_id);
          return -1;
        }
      send_ans_key(from, to, pktkey);
    }

  /* Update our copy of the origin's packet key */

  if(from->cipher_pktkey)
    free(from->cipher_pktkey);

  from->cipher_pktkey = xstrdup(pktkey);
  keylength /= 2;
  hex2bin(from->cipher_pktkey, from->cipher_pktkey, keylength);
  from->cipher_pktkey[keylength] = '\0';

  from->status.validkey = 1;
  from->status.waitingforkey = 0;
  
  flush_queue(from);
cp
  return 0;
}

int send_tcppacket(connection_t *cl, vpn_packet_t *packet)
{
  int x;
cp  
  /* Evil hack. */

  x = send_request(cl->nexthop, "%d %hd", PACKET, packet->len);

  if(x)
    return x;
cp
  return send_meta(cl, packet->data, packet->len);
}

int tcppacket_h(connection_t *cl)
{
  short int len;
cp  
  if(sscanf(cl->buffer, "%*d %hd", &len) != 1)
    {
      syslog(LOG_ERR, _("Got bad PACKET from %s (%s)"), cl->name, cl->hostname);
      return -1;
    }

  /* Set reqlen to len, this will tell receive_meta() that a tcppacket is coming. */

  cl->tcplen = len;
cp
  return 0;
}

/* Jumptable for the request handlers */

int (*request_handlers[])(connection_t*) = {
  id_h, metakey_h, challenge_h, chal_reply_h,
  status_h, error_h, termreq_h,
  ping_h, pong_h,
  add_host_h, del_host_h,
  add_subnet_h, del_subnet_h,
  key_changed_h, req_key_h, ans_key_h,
  tcppacket_h,
};

/* Request names */

char (*request_name[]) = {
  "ID", "METAKEY", "CHALLENGE", "CHAL_REPLY",
  "STATUS", "ERROR", "TERMREQ",
  "PING", "PONG",
  "ADD_HOST", "DEL_HOST",
  "ADD_SUBNET", "DEL_SUBNET",
  "KEY_CHANGED", "REQ_KEY", "ANS_KEY",
  "PACKET",
};

/* Status strings */

char (*status_text[]) = {
  "Warning",
};

/* Error strings */

char (*error_text[]) = {
  "Error",
};
