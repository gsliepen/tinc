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

    $Id: protocol.c,v 1.28.4.112 2001/10/28 22:42:49 guus Exp $
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

#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/evp.h>

#ifndef HAVE_RAND_PSEUDO_BYTES
#define RAND_pseudo_bytes RAND_bytes
#endif

#include "conf.h"
#include "net.h"
#include "netutl.h"
#include "protocol.h"
#include "meta.h"
#include "connection.h"
#include "node.h"
#include "edge.h"

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
  request = va_arg(args, int);
  va_end(args);

  if(len < 0 || len > MAXBUFSIZE-1)
    {
      syslog(LOG_ERR, _("Output buffer overflow while sending %s to %s (%s)"), request_name[request], c->name, c->hostname);
      return -1;
    }

  if(debug_lvl >= DEBUG_PROTOCOL)
    {
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

/* The authentication protocol is described in detail in doc/SECURITY2,
   the rest will be described in doc/PROTOCOL. */

int send_id(connection_t *c)
{
cp
  return send_request(c, "%d %s %d", ID, myself->connection->name, myself->connection->protocol_version);
}

int id_h(connection_t *c)
{
  char name[MAX_STRING_SIZE];
int bla;
cp
  if(sscanf(c->buffer, "%*d "MAX_STRING" %d", name, &c->protocol_version) != 2)
    {
       syslog(LOG_ERR, _("Got bad %s from %s (%s)"), "ID", c->name, c->hostname);
       return -1;
    }

  /* Check if identity is a valid name */

  if(check_id(name))
    {
      syslog(LOG_ERR, _("Got bad %s from %s (%s): %s"), "ID", c->name, c->hostname, "invalid name");
      return -1;
    }

  /* If we set c->name in advance, make sure we are connected to the right host */
  
  if(c->name)
    {
      if(strcmp(c->name, name))
        {
          syslog(LOG_ERR, _("Peer %s is %s instead of %s"), c->hostname, name, c->name);
          return -1;
        }
    }
  else
    c->name = xstrdup(name);

  /* Check if version matches */

  if(c->protocol_version != myself->connection->protocol_version)
    {
      syslog(LOG_ERR, _("Peer %s (%s) uses incompatible version %d"),
             c->name, c->hostname, c->protocol_version);
      return -1;
    }
  
  if(bypass_security)
    {
      if(!c->config_tree)
        init_configuration(&c->config_tree);
      c->allow_request = ACK;
      return send_ack(c);
    }

  if(!c->config_tree)
    {
      init_configuration(&c->config_tree);

      if((bla = read_connection_config(c)))
        {
          syslog(LOG_ERR, _("Peer %s had unknown identity (%s)"), c->hostname, c->name);
          return -1;
        }

      if(read_rsa_public_key(c))
        {
          return -1;
        }
    }

  c->allow_request = METAKEY;
cp
  return send_metakey(c);
}

int send_metakey(connection_t *c)
{
  char *buffer;
  int len, x;
cp
  len = RSA_size(c->rsa_key);

  /* Allocate buffers for the meta key */

  buffer = xmalloc(len*2+1);

  if(!c->outkey)
    c->outkey = xmalloc(len);
    
  if(!c->outctx)
    c->outctx = xmalloc(sizeof(*c->outctx));
cp
  /* Copy random data to the buffer */

  RAND_bytes(c->outkey, len);

  /* The message we send must be smaller than the modulus of the RSA key.
     By definition, for a key of k bits, the following formula holds:
     
       2^(k-1) <= modulus < 2^(k)
     
     Where ^ means "to the power of", not "xor".
     This means that to be sure, we must choose our message < 2^(k-1).
     This can be done by setting the most significant bit to zero.
  */
  
  c->outkey[0] &= 0x7F;
  
  if(debug_lvl >= DEBUG_SCARY_THINGS)
    {
      bin2hex(c->outkey, buffer, len);
      buffer[len*2] = '\0';
      syslog(LOG_DEBUG, _("Generated random meta key (unencrypted): %s"), buffer);
    }

  /* Encrypt the random data
  
     We do not use one of the PKCS padding schemes here.
     This is allowed, because we encrypt a totally random string
     with a length equal to that of the modulus of the RSA key.
  */
  
  if(RSA_public_encrypt(len, c->outkey, buffer, c->rsa_key, RSA_NO_PADDING) != len)
    {
      syslog(LOG_ERR, _("Error during encryption of meta key for %s (%s)"), c->name, c->hostname);
      free(buffer);
      return -1;
    }
cp
  /* Convert the encrypted random data to a hexadecimal formatted string */

  bin2hex(buffer, buffer, len);
  buffer[len*2] = '\0';

  /* Send the meta key */

  x = send_request(c, "%d %s", METAKEY, buffer);
  free(buffer);

  /* Further outgoing requests are encrypted with the key we just generated */

  EVP_EncryptInit(c->outctx, EVP_bf_cfb(),
                  c->outkey + len - EVP_bf_cfb()->key_len,
                  c->outkey + len - EVP_bf_cfb()->key_len - EVP_bf_cfb()->iv_len);

  c->status.encryptout = 1;
cp
  return x;
}

int metakey_h(connection_t *c)
{
  char buffer[MAX_STRING_SIZE];
  int len;
cp
  if(sscanf(c->buffer, "%*d "MAX_STRING, buffer) != 1)
    {
       syslog(LOG_ERR, _("Got bad %s from %s (%s)"), "METAKEY", c->name, c->hostname);
       return -1;
    }

  len = RSA_size(myself->connection->rsa_key);

  /* Check if the length of the meta key is all right */

  if(strlen(buffer) != len*2)
    {
      syslog(LOG_ERR, _("Possible intruder %s (%s): %s"), c->name, c->hostname, "wrong keylength");
      return -1;
    }

  /* Allocate buffers for the meta key */

  if(!c->inkey)
    c->inkey = xmalloc(len);

  if(!c->inctx)
    c->inctx = xmalloc(sizeof(*c->inctx));

  /* Convert the challenge from hexadecimal back to binary */

  hex2bin(buffer,buffer,len);

  /* Decrypt the meta key */
  
  if(RSA_private_decrypt(len, buffer, c->inkey, myself->connection->rsa_key, RSA_NO_PADDING) != len)	/* See challenge() */
    {
      syslog(LOG_ERR, _("Error during encryption of meta key for %s (%s)"), c->name, c->hostname);
      return -1;
    }

  if(debug_lvl >= DEBUG_SCARY_THINGS)
    {
      bin2hex(c->inkey, buffer, len);
      buffer[len*2] = '\0';
      syslog(LOG_DEBUG, _("Received random meta key (unencrypted): %s"), buffer);
    }

  /* All incoming requests will now be encrypted. */

  EVP_DecryptInit(c->inctx, EVP_bf_cfb(),
                  c->inkey + len - EVP_bf_cfb()->key_len,
                  c->inkey + len - EVP_bf_cfb()->key_len - EVP_bf_cfb()->iv_len);
  
  c->status.decryptin = 1;

  c->allow_request = CHALLENGE;
cp
  return send_challenge(c);
}

int send_challenge(connection_t *c)
{
  char *buffer;
  int len, x;
cp
  /* CHECKME: what is most reasonable value for len? */

  len = RSA_size(c->rsa_key);

  /* Allocate buffers for the challenge */

  buffer = xmalloc(len*2+1);

  if(c->hischallenge)
    free(c->hischallenge);
    
  c->hischallenge = xmalloc(len);
cp
  /* Copy random data to the buffer */

  RAND_bytes(c->hischallenge, len);

cp
  /* Convert to hex */

  bin2hex(c->hischallenge, buffer, len);
  buffer[len*2] = '\0';

cp
  /* Send the challenge */

  x = send_request(c, "%d %s", CHALLENGE, buffer);
  free(buffer);
cp
  return x;
}

int challenge_h(connection_t *c)
{
  char buffer[MAX_STRING_SIZE];
  int len;
cp
  if(sscanf(c->buffer, "%*d "MAX_STRING, buffer) != 1)
    {
       syslog(LOG_ERR, _("Got bad %s from %s (%s)"), "CHALLENGE", c->name, c->hostname);
       return -1;
    }

  len = RSA_size(myself->connection->rsa_key);

  /* Check if the length of the challenge is all right */

  if(strlen(buffer) != len*2)
    {
      syslog(LOG_ERR, _("Possible intruder %s (%s): %s"), c->name, c->hostname, "wrong challenge length");
      return -1;
    }

  /* Allocate buffers for the challenge */

  if(!c->mychallenge)
    c->mychallenge = xmalloc(len);

  /* Convert the challenge from hexadecimal back to binary */

  hex2bin(buffer,c->mychallenge,len);

  c->allow_request = CHAL_REPLY;

  /* Rest is done by send_chal_reply() */
cp
  return send_chal_reply(c);
}

int send_chal_reply(connection_t *c)
{
  char hash[SHA_DIGEST_LENGTH*2+1];
cp
  /* Calculate the hash from the challenge we received */

  SHA1(c->mychallenge, RSA_size(myself->connection->rsa_key), hash);

  /* Convert the hash to a hexadecimal formatted string */

  bin2hex(hash,hash,SHA_DIGEST_LENGTH);
  hash[SHA_DIGEST_LENGTH*2] = '\0';

  /* Send the reply */

cp
  return send_request(c, "%d %s", CHAL_REPLY, hash);
}

int chal_reply_h(connection_t *c)
{
  char hishash[MAX_STRING_SIZE];
  char myhash[SHA_DIGEST_LENGTH];
cp
  if(sscanf(c->buffer, "%*d "MAX_STRING, hishash) != 1)
    {
       syslog(LOG_ERR, _("Got bad %s from %s (%s)"), "CHAL_REPLY", c->name, c->hostname);
       return -1;
    }

  /* Check if the length of the hash is all right */

  if(strlen(hishash) != SHA_DIGEST_LENGTH*2)
    {
      syslog(LOG_ERR, _("Possible intruder %s (%s): %s"), c->name, c->hostname, _("wrong challenge reply length"));
      return -1;
    }

  /* Convert the hash to binary format */

  hex2bin(hishash, hishash, SHA_DIGEST_LENGTH);

  /* Calculate the hash from the challenge we sent */

  SHA1(c->hischallenge, RSA_size(c->rsa_key), myhash);

  /* Verify the incoming hash with the calculated hash */

  if(memcmp(hishash, myhash, SHA_DIGEST_LENGTH))
    {
      syslog(LOG_ERR, _("Possible intruder %s (%s): %s"), c->name, c->hostname, _("wrong challenge reply"));
      if(debug_lvl >= DEBUG_SCARY_THINGS)
        {
          bin2hex(myhash, hishash, SHA_DIGEST_LENGTH);
          hishash[SHA_DIGEST_LENGTH*2] = '\0';
          syslog(LOG_DEBUG, _("Expected challenge reply: %s"), hishash);
        }
      return -1;
    }

  /* Identity has now been positively verified.
     Send an acknowledgement with the rest of the information needed.
   */

  c->allow_request = ACK;
cp
  return send_ack(c);
}

int send_ack(connection_t *c)
{
  /* ACK message contains rest of the information the other end needs
     to create node_t and edge_t structures. */

  struct timeval now;

  /* Estimate weight */
  
  gettimeofday(&now, NULL);
  c->estimated_weight = (now.tv_sec - c->start.tv_sec) * 1000 + (now.tv_usec - c->start.tv_usec) / 1000;
cp
  return send_request(c, "%d %hd %d", ACK, myself->port, c->estimated_weight);
}

int ack_h(connection_t *c)
{
  port_t port;
  int weight;
  node_t *n;
  subnet_t *s;
  avl_node_t *node, *node2;
cp
  if(sscanf(c->buffer, "%*d %hd %d", &port, &weight) != 2)
    {
       syslog(LOG_ERR, _("Got bad %s from %s (%s)"), "ACK", c->name, c->hostname);
       return -1;
    }

  /* Check if we already have a node_t for him */

  n = lookup_node(c->name);
  
  if(!n)
    {
      n = new_node();
      n->name = xstrdup(c->name);
      n->hostname = xstrdup(c->hostname);
      n->port = port;

      /* FIXME: Also check if no other tinc daemon uses the same IP and port for UDP traffic */

      node_add(n);
    }
  else
    {
      if(n->connection)
        {
          /* Oh dear, we already have a connection to this node. */
          syslog(LOG_DEBUG, _("Established a second connection with %s (%s), closing old connection"), n->name, n->hostname);
          terminate_connection(n->connection, 0);
        }
          
      /* FIXME: check if information in existing node matches that of the other end of this connection */
    }
  
  n->connection = c;
  c->node = n;
  
  /* Check some options
  
  if((cfg = get_config_val(c->config, config_indirectdata)))
    {
      if(cfg->data.val == stupid_true)
        c->options |= OPTION_INDIRECT;
    }

  if((cfg = get_config_val(c->config, config_tcponly)))
    {
      if(cfg->data.val == stupid_true)
        c->options |= OPTION_TCPONLY;
    }

  if((myself->options | c->options) & OPTION_INDIRECT)
    c->via = myself;
  else
    c->via = c;

  */

  /* Create a edge_t for this connection */

  c->edge = new_edge();
  
  c->edge->from = myself;
  c->edge->to = n;
  c->edge->weight = (weight + c->estimated_weight) / 2;
  c->edge->connection = c;

  edge_add(c->edge);

  /* Activate this connection */

  c->allow_request = ALL;
  c->status.active = 1;

  if(debug_lvl >= DEBUG_CONNECTIONS)
    syslog(LOG_NOTICE, _("Connection with %s (%s) activated"), c->name, c->hostname);

cp
  /* Send him our subnets */
  
  for(node = myself->subnet_tree->head; node; node = node->next)
    {
      s = (subnet_t *)node->data;
      send_add_subnet(c, s);
    }

  /* And send him all known nodes and their subnets */
  
  for(node = node_tree->head; node; node = node->next)
    {
      n = (node_t *)node->data;

      if(n == c->node || n == myself)
        continue;

      /* Notify others of this connection */

      if(n->connection)
        send_add_node(n->connection, c->node);

      /* Notify new connection of everything we know */

      send_add_node(c, n);

      for(node2 = c->node->subnet_tree->head; node2; node2 = node2->next)
        {
          s = (subnet_t *)node2->data;
          send_add_subnet(c, s);
        }
    }
cp
  return 0;
}



/* Address and subnet information exchange */

int send_add_subnet(connection_t *c, subnet_t *subnet)
{
  int x;
  char *netstr;
cp
  x = send_request(c, "%d %s %s", ADD_SUBNET,
                      subnet->owner->name, netstr = net2str(subnet));
  free(netstr);
cp
  return x;
}

int add_subnet_h(connection_t *c)
{
  char subnetstr[MAX_STRING_SIZE];
  char name[MAX_STRING_SIZE];
  node_t *owner;
  connection_t *other;
  subnet_t *s;
  avl_node_t *node;
cp
  if(sscanf(c->buffer, "%*d "MAX_STRING" "MAX_STRING, name, subnetstr) != 2)
    {
      syslog(LOG_ERR, _("Got bad %s from %s (%s)"), "ADD_SUBNET", c->name, c->hostname);
      return -1;
    }

  /* Check if owner name is a valid */

  if(check_id(name))
    {
      syslog(LOG_ERR, _("Got bad %s from %s (%s): %s"), "ADD_SUBNET", c->name, c->hostname, _("invalid name"));
      return -1;
    }

  /* Check if subnet string is valid */

  if(!(s = str2net(subnetstr)))
    {
      syslog(LOG_ERR, _("Got bad %s from %s (%s): %s"), "ADD_SUBNET", c->name, c->hostname, _("invalid subnet string"));
      return -1;
    }

  /* Check if the owner of the new subnet is in the connection list */

  if(!(owner = lookup_node(name)))
    {
      syslog(LOG_ERR, _("Got ADD_SUBNET from %s (%s) for %s which is not in our connection list"),
             name, c->name, c->hostname);
      return -1;
    }

  /* If everything is correct, add the subnet to the list of the owner */

  subnet_add(owner, s);

  /* Tell the rest */
  
  for(node = connection_tree->head; node; node = node->next)
    {
      other = (connection_t *)node->data;
      if(other->status.active && other != c)
        send_add_subnet(other, s);
    }
cp
  return 0;
}

int send_del_subnet(connection_t *c, subnet_t *s)
{
  int x;
  char *netstr;
cp
  x = send_request(c, "%d %s %s", DEL_SUBNET, s->owner->name, netstr = net2str(s));
  free(netstr);
cp
  return x;
}

int del_subnet_h(connection_t *c)
{
  char subnetstr[MAX_STRING_SIZE];
  char name[MAX_STRING_SIZE];
  node_t *owner;
  connection_t *other;
  subnet_t *s, *find;
  avl_node_t *node;
cp
  if(sscanf(c->buffer, "%*d "MAX_STRING" "MAX_STRING, name, subnetstr) != 3)
    {
      syslog(LOG_ERR, _("Got bad %s from %s (%s)"), "DEL_SUBNET", c->name, c->hostname);
      return -1;
    }

  /* Check if owner name is a valid */

  if(check_id(name))
    {
      syslog(LOG_ERR, _("Got bad %s from %s (%s): %s"), "DEL_SUBNET", c->name, c->hostname, _("invalid name"));
      return -1;
    }

  /* Check if subnet string is valid */

  if(!(s = str2net(subnetstr)))
    {
      syslog(LOG_ERR, _("Got bad %s from %s (%s): %s"), "DEL_SUBNET", c->name, c->hostname, _("invalid subnet string"));
      return -1;
    }

  /* Check if the owner of the new subnet is in the connection list */

  if(!(owner = lookup_node(name)))
    {
      syslog(LOG_ERR, _("Got %s from %s (%s) for %s which is not in our connection list"),
             "DEL_SUBNET", c->name, c->hostname, name);
      return -1;
    }

  /* If everything is correct, delete the subnet from the list of the owner */

  find = lookup_subnet(owner, s);
  
  if(!find)
    {
      syslog(LOG_ERR, _("Got %s from %s (%s) for %s which does not appear in his subnet tree"),
             "DEL_SUBNET", c->name, c->hostname, name);
      return -1;
    }
  
  subnet_del(owner, s);

  /* Tell the rest */
  
  for(node = connection_tree->head; node; node = node->next)
    {
      other = (connection_t *)node->data;
      if(other->status.active && other != c)
        send_del_subnet(other, s);
    }
cp
  return 0;
}

/* New and closed connections notification */

int send_add_node(connection_t *c, node_t *n)
{
cp
  return send_request(c, "%d %s %lx:%d", ADD_NODE,
                      n->name, n->address, n->port);
}

int add_node_h(connection_t *c)
{
  connection_t *other;
  node_t *n;
  char name[MAX_STRING_SIZE];
  ipv4_t address;
  port_t port;
  avl_node_t *node;
cp
  if(sscanf(c->buffer, "%*d "MAX_STRING" %lx:%hd", name, &address, &port) != 3)
    {
       syslog(LOG_ERR, _("Got bad %s from %s (%s)"), "ADD_NODE", c->name, c->hostname);
       return -1;
    }

  /* Check if identity is a valid name */

  if(check_id(name))
    {
      syslog(LOG_ERR, _("Got bad %s from %s (%s): %s"), "ADD_NODE", c->name, c->hostname, _("invalid name"));
      return -1;
    }

  /* Check if node already exists */
  
  n = lookup_node(name);
  
  if(n)
    {
      /* Check if it matches */
    }
  else
    {
      n = new_node();
      n->name = xstrdup(name);
      n->address = address;
      n->port = port;
      node_add(n);
    }

  /* Tell the rest about the new node */

  for(node = connection_tree->head; node; node = node->next)
    {
      other = (connection_t *)node->data;
      if(other->status.active && other !=c)
        send_add_node(other, n);
    }

cp
  return 0;
}

int send_del_node(connection_t *c, node_t *n)
{
cp
  return send_request(c, "%d %s %lx:%d", DEL_NODE,
                      n->name, n->address, n->port);
}

int del_node_h(connection_t *c)
{
  node_t *n;
  char name[MAX_STRING_SIZE];
  ipv4_t address;
  port_t port;
  connection_t *other;
  avl_node_t *node;
cp
  if(sscanf(c->buffer, "%*d "MAX_STRING" %lx:%hd", name, &address, &port) != 3)
    {
      syslog(LOG_ERR, _("Got bad %s from %s (%s)"), "DEL_NODE",
             c->name, c->hostname);
      return -1;
    }

  /* Check if identity is a valid name */

  if(check_id(name))
    {
      syslog(LOG_ERR, _("Got bad %s from %s (%s): %s"), "DEL_NODE", c->name, c->hostname, _("invalid name"));
      return -1;
    }

  /* Check if somebody tries to delete ourself */

  if(!strcmp(name, myself->name))
    {
      syslog(LOG_ERR, _("Got %s from %s (%s) for ourself!"), "DEL_NODE",
             c->name, c->hostname);
      return -1;
    }

  /* Check if the deleted host exists */

  n = lookup_node(name);

  if(!n)
    {
      syslog(LOG_WARNING, _("Got %s from %s (%s) for %s which does not exist"), "DEL_NODE", c->name, c->hostname, n->name);
      return 0;
    }
  
  /* Check if the rest matches */
  
  if(address != n->address || port != n->port)
    {
      syslog(LOG_WARNING, _("Got %s from %s (%s) for %s which doesn't match"), "DEL_NODE", c->name, c->hostname, n->name);
      return 0;
    }

  /* Tell the rest about the deleted node */

  for(node = connection_tree->head; node; node = node->next)
    {
      other = (connection_t *)node->data;
      if(other->status.active && other != c)
        send_del_node(other, n);
    }

  /* Delete the node */
  
  node_del(n);
cp
  return 0;
}

/* Edges */

int send_add_edge(connection_t *c, edge_t *e)
{
cp
  return send_request(c, "%d %s %s %lx", ADD_NODE,
                      e->from->name, e->to->name, e->options);
}

int add_edge_h(connection_t *c)
{
  connection_t *other;
  edge_t *e;
  node_t *from, *to;
  char from_name[MAX_STRING_SIZE];
  char to_name[MAX_STRING_SIZE];
  long int options;
  avl_node_t *node;
cp
  if(sscanf(c->buffer, "%*d "MAX_STRING" "MAX_STRING" %lx", from_name, to_name, &options) != 3)
    {
       syslog(LOG_ERR, _("Got bad %s from %s (%s)"), "ADD_EDGE", c->name, c->hostname);
       return -1;
    }

  /* Check if names are valid */

  if(check_id(from_name))
    {
      syslog(LOG_ERR, _("Got bad %s from %s (%s): %s"), "ADD_EDGE", c->name, c->hostname, _("invalid name"));
      return -1;
    }

  if(check_id(to_name))
    {
      syslog(LOG_ERR, _("Got bad %s from %s (%s): %s"), "ADD_EDGE", c->name, c->hostname, _("invalid name"));
      return -1;
    }

  /* Lookup nodes */

  from = lookup_node(from_name);
  
  if(!from)
    {
      syslog(LOG_ERR, _("Got bad %s from %s (%s): %s"), "ADD_EDGE", c->name, c->hostname, _("unknown node"));
      return -1;
    }

  to = lookup_node(to_name);
  
  if(!to)
    {
      syslog(LOG_ERR, _("Got bad %s from %s (%s): %s"), "ADD_EDGE", c->name, c->hostname, _("unknown node"));
      return -1;
    }

  /* Check if node already exists */
  
  e = lookup_edge(from, to);
  
  if(e)
    {
      /* Check if it matches */
    }
  else
    {
      e = new_edge();
      e->from = from;
      e->to = to;
      e->options = options;
      edge_add(e);
    }

  /* Tell the rest about the new edge */

  for(node = connection_tree->head; node; node = node->next)
    {
      other = (connection_t *)node->data;
      if(other->status.active && other != c)
        send_add_edge(other, e);
    }

cp
  return 0;
}

int send_del_edge(connection_t *c, edge_t *e)
{
cp
  return send_request(c, "%d %s %s %lx", DEL_EDGE,
                      e->from->name, e->to->name, e->options);
}

int del_edge_h(connection_t *c)
{
  edge_t *e;
  char from_name[MAX_STRING_SIZE];
  char to_name[MAX_STRING_SIZE];
  node_t *from, *to;
  long int options;
  connection_t *other;
  avl_node_t *node;
cp
  if(sscanf(c->buffer, "%*d "MAX_STRING" "MAX_STRING" %lx", from_name, to_name, &options) != 3)
    {
      syslog(LOG_ERR, _("Got bad %s from %s (%s)"), "DEL_EDGE",
             c->name, c->hostname);
      return -1;
    }

  /* Check if names are valid */

  if(check_id(from_name))
    {
      syslog(LOG_ERR, _("Got bad %s from %s (%s): %s"), "DEL_EDGE", c->name, c->hostname, _("invalid name"));
      return -1;
    }

  if(check_id(to_name))
    {
      syslog(LOG_ERR, _("Got bad %s from %s (%s): %s"), "DEL_EDGE", c->name, c->hostname, _("invalid name"));
      return -1;
    }

  /* Lookup nodes */

  from = lookup_node(from_name);
  
  if(!from)
    {
      syslog(LOG_ERR, _("Got bad %s from %s (%s): %s"), "DEL_EDGE", c->name, c->hostname, _("unknown node"));
      return -1;
    }

  to = lookup_node(to_name);
  
  if(!to)
    {
      syslog(LOG_ERR, _("Got bad %s from %s (%s): %s"), "DEL_EDGE", c->name, c->hostname, _("unknown node"));
      return -1;
    }

  /* Check if edge exists */
  
  e = lookup_edge(from, to);
  
  if(e)
    {
      /* Check if it matches */
    }
  else
    {
      syslog(LOG_ERR, _("Got bad %s from %s (%s): %s"), "DEL_EDGE", c->name, c->hostname, _("unknown edge"));
      return -1;
    }

  /* Tell the rest about the deleted edge */

  for(node = connection_tree->head; node; node = node->next)
    {
      other = (connection_t *)node->data;
      if(other->status.active && other != c)
        send_del_edge(other, e);
    }

  /* Delete the edge */
  
  edge_del(e);
cp
  return 0;
}


/* Status and error notification routines */

int send_status(connection_t *c, int statusno, char *statusstring)
{
cp
  if(!statusstring)
    statusstring = status_text[statusno];
cp
  return send_request(c, "%d %d %s", STATUS, statusno, statusstring);
}

int status_h(connection_t *c)
{
  int statusno;
  char statusstring[MAX_STRING_SIZE];
cp
  if(sscanf(c->buffer, "%*d %d "MAX_STRING, &statusno, statusstring) != 2)
    {
       syslog(LOG_ERR, _("Got bad %s from %s (%s)"), "STATUS",
              c->name, c->hostname);
       return -1;
    }

  if(debug_lvl >= DEBUG_STATUS)
    {
      syslog(LOG_NOTICE, _("Status message from %s (%s): %s: %s"),
             c->name, c->hostname, status_text[statusno], statusstring);
    }

cp
  return 0;
}

int send_error(connection_t *c, int err, char *errstring)
{
cp
  if(!errstring)
    errstring = strerror(err);
  return send_request(c, "%d %d %s", ERROR, err, errstring);
}

int error_h(connection_t *c)
{
  int err;
  char errorstring[MAX_STRING_SIZE];
cp
  if(sscanf(c->buffer, "%*d %d "MAX_STRING, &err, errorstring) != 2)
    {
       syslog(LOG_ERR, _("Got bad %s from %s (%s)"), "ERROR",
              c->name, c->hostname);
       return -1;
    }

  if(debug_lvl >= DEBUG_ERROR)
    {
      syslog(LOG_NOTICE, _("Error message from %s (%s): %s: %s"),
             c->name, c->hostname, strerror(err), errorstring);
    }

  terminate_connection(c, c->status.active);
cp
  return 0;
}

int send_termreq(connection_t *c)
{
cp
  return send_request(c, "%d", TERMREQ);
}

int termreq_h(connection_t *c)
{
cp
  terminate_connection(c, c->status.active);
cp
  return 0;
}

int send_ping(connection_t *c)
{
  char salt[SALTLEN*2+1];
cp
  c->status.pinged = 1;
  c->last_ping_time = time(NULL);
  RAND_pseudo_bytes(salt, SALTLEN);
  bin2hex(salt, salt, SALTLEN);
  salt[SALTLEN*2] = '\0';
cp
  return send_request(c, "%d %s", PING, salt);
}

int ping_h(connection_t *c)
{
cp
  return send_pong(c);
}

int send_pong(connection_t *c)
{
  char salt[SALTLEN*2+1];
cp
  RAND_pseudo_bytes(salt, SALTLEN);
  bin2hex(salt, salt, SALTLEN);
  salt[SALTLEN*2] = '\0';
cp
  return send_request(c, "%d %s", PONG, salt);
}

int pong_h(connection_t *c)
{
cp
  c->status.pinged = 0;
cp
  return 0;
}

/* Key exchange */

int send_key_changed(connection_t *c, node_t *n)
{
  connection_t *other;
  avl_node_t *node;
cp
  /* Only send this message if some other daemon requested our key previously.
     This reduces unnecessary key_changed broadcasts.
  */

  if(n == myself && !mykeyused)
    return 0;

  for(node = connection_tree->head; node; node = node->next)
    {
      other = (connection_t *)node->data;
      if(other != c && other->status.active)
        send_request(other, "%d %s", KEY_CHANGED, n->name);
    }
cp
  return 0;
}

int key_changed_h(connection_t *c)
{
  char name[MAX_STRING_SIZE];
  node_t *n;
cp
  if(sscanf(c->buffer, "%*d "MAX_STRING, name) != 1)
    {
      syslog(LOG_ERR, _("Got bad %s from %s (%s)"), "KEY_CHANGED",
             c->name, c->hostname);
      return -1;
    }

  n = lookup_node(name);

  if(!n)
    {
      syslog(LOG_ERR, _("Got %s from %s (%s) origin %s which does not exist"), "KEY_CHANGED",
             c->name, c->hostname, name);
      return -1;
    }

  n->status.validkey = 0;
  n->status.waitingforkey = 0;

  send_key_changed(c, n);
cp
  return 0;
}

int send_req_key(connection_t *c, node_t *from, node_t *to)
{
cp
  return send_request(c, "%d %s %s", REQ_KEY,
                      from->name, to->name);
}

int req_key_h(connection_t *c)
{
  char from_name[MAX_STRING_SIZE];
  char to_name[MAX_STRING_SIZE];
  node_t *from, *to;
  char key[MAX_STRING_SIZE];
cp
  if(sscanf(c->buffer, "%*d "MAX_STRING" "MAX_STRING, from_name, to_name) != 2)
    {
       syslog(LOG_ERR, _("Got bad %s from %s (%s)"), "REQ_KEY",
              c->name, c->hostname);
       return -1;
    }

  from = lookup_node(from_name);

  if(!from)
    {
      syslog(LOG_ERR, _("Got %s from %s (%s) origin %s which does not exist in our connection list"), "REQ_KEY",
             c->name, c->hostname, from_name);
      return -1;
    }

  to = lookup_node(to_name);
  
  if(!to)
    {
      syslog(LOG_ERR, _("Got %s from %s (%s) destination %s which does not exist in our connection list"), "REQ_KEY",
             c->name, c->hostname, to_name);
      return -1;
    }

  /* Check if this key request is for us */

  if(to == myself)	/* Yes, send our own key back */
    {
      bin2hex(myself->key, key, myself->keylength);
      key[myself->keylength * 2] = '\0';
      send_ans_key(c, myself, from, key);
      mykeyused = 1;
    }
  else
    {
      if(to->status.validkey)	/* Proxy keys */
        {
          bin2hex(to->key, key, to->keylength);
          key[to->keylength * 2] = '\0';
          send_ans_key(c, to, from, key);
        }
      else
        send_req_key(to->nexthop->connection, from, to);
    }

cp
  return 0;
}

int send_ans_key(connection_t *c, node_t *from, node_t *to, char *key)
{
cp
  return send_request(c, "%d %s %s %s", ANS_KEY,
                      from->name, to->name, key);
}

int ans_key_h(connection_t *c)
{
  char from_name[MAX_STRING_SIZE];
  char to_name[MAX_STRING_SIZE];
  char key[MAX_STRING_SIZE];
  int keylength;
  node_t *from, *to;
cp
  if(sscanf(c->buffer, "%*d "MAX_STRING" "MAX_STRING" "MAX_STRING, from_name, to_name, key) != 3)
    {
       syslog(LOG_ERR, _("Got bad %s from %s (%s)"), "ANS_KEY",
              c->name, c->hostname);
       return -1;
    }

  from = lookup_node(from_name);

  if(!from)
    {
      syslog(LOG_ERR, _("Got %s from %s (%s) origin %s which does not exist in our connection list"), "ANS_KEY",
             c->name, c->hostname, from_name);
      return -1;
    }

  to = lookup_node(to_name);

  if(!to)
    {
      syslog(LOG_ERR, _("Got %s from %s (%s) destination %s which does not exist in our connection list"), "ANS_KEY",
             c->name, c->hostname, to_name);
      return -1;
    }

  /* Check correctness of packet key */

  keylength = strlen(key);

  if(keylength != from->keylength * 2)
    {
      syslog(LOG_ERR, _("Got bad %s from %s (%s) origin %s: %s"), "ANS_KEY",
             c->name, c->hostname, from->name, _("invalid key length"));
      return -1;
    }

  /* Forward it if necessary */

  if(to != myself)
    {
      send_ans_key(to->nexthop->connection, from, to, key);
    }

  /* Update our copy of the origin's packet key */

  if(from->key)
    free(from->key);

  from->key = xstrdup(key);
  keylength /= 2;
  hex2bin(from->key, from->key, keylength);
  from->key[keylength] = '\0';

  from->status.validkey = 1;
  from->status.waitingforkey = 0;
  
  flush_queue(from);
cp
  return 0;
}

int send_tcppacket(connection_t *c, vpn_packet_t *packet)
{
  int x;
cp  
  /* Evil hack. */

  x = send_request(c, "%d %hd", PACKET, packet->len);

  if(x)
    return x;
cp
  return send_meta(c, packet->data, packet->len);
}

int tcppacket_h(connection_t *c)
{
  short int len;
cp  
  if(sscanf(c->buffer, "%*d %hd", &len) != 1)
    {
      syslog(LOG_ERR, _("Got bad %s from %s (%s)"), "PACKET", c->name, c->hostname);
      return -1;
    }

  /* Set reqlen to len, this will tell receive_meta() that a tcppacket is coming. */

  c->tcplen = len;
cp
  return 0;
}

/* Jumptable for the request handlers */

int (*request_handlers[])(connection_t*) = {
  id_h, metakey_h, challenge_h, chal_reply_h, ack_h,
  status_h, error_h, termreq_h,
  ping_h, pong_h,
  add_node_h, del_node_h,
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
  "ADD_NODE", "DEL_NODE",
  "ADD_SUBNET", "DEL_SUBNET",
  "ADD_EDGE", "DEL_EDGE",
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
