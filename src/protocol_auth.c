/*
    protocol_auth.c -- handle the meta-protocol, authentication
    Copyright (C) 1999-2002 Ivo Timmermans <itimmermans@bigfoot.com>,
                  2000-2002 Guus Sliepen <guus@sliepen.warande.net>

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

    $Id: protocol_auth.c,v 1.1.4.8 2002/03/27 15:26:44 guus Exp $
*/

#include "config.h"

#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <stdio.h>
#include <stdarg.h>
#include <errno.h>

#include <utils.h>
#include <xalloc.h>
#include <avl_tree.h>

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
#include "graph.h"

#include "system.h"

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
    }

  if(read_rsa_public_key(c))
    {
      return -1;
    }

  /* Check some options */
  
  if((get_config_bool(lookup_config(c->config_tree, "IndirectData"), &bla) && bla) || myself->options & OPTION_INDIRECT)
        c->options |= OPTION_INDIRECT;

  if((get_config_bool(lookup_config(c->config_tree, "TCPOnly"), &bla) && bla) || myself->options & OPTION_TCPONLY)
        c->options |= OPTION_TCPONLY | OPTION_INDIRECT;

  c->allow_request = METAKEY;
cp
  return send_metakey(c);
}

int send_metakey(connection_t *c)
{
  char buffer[MAX_STRING_SIZE];
  int len, x;
cp
  len = RSA_size(c->rsa_key);

  /* Allocate buffers for the meta key */

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
      return -1;
    }
cp
  /* Convert the encrypted random data to a hexadecimal formatted string */

  bin2hex(buffer, buffer, len);
  buffer[len*2] = '\0';

  /* Send the meta key */

  x = send_request(c, "%d %d %d %d %d %s", METAKEY,
                   c->outcipher?c->outcipher->nid:0, c->outdigest?c->outdigest->type:0,
		   c->outmaclength, c->outcompression, buffer);

  /* Further outgoing requests are encrypted with the key we just generated */

  if(c->outcipher)
    {
      EVP_EncryptInit(c->outctx, c->outcipher,
                      c->outkey + len - c->outcipher->key_len,
                      c->outkey + len - c->outcipher->key_len - c->outcipher->iv_len);

      c->status.encryptout = 1;
    }
cp
  return x;
}

int metakey_h(connection_t *c)
{
  char buffer[MAX_STRING_SIZE];
  int cipher, digest, maclength, compression;
  int len;
cp
  if(sscanf(c->buffer, "%*d %d %d %d %d "MAX_STRING, &cipher, &digest, &maclength, &compression, buffer) != 5)
    {
       syslog(LOG_ERR, _("Got bad %s from %s (%s)"), "METAKEY", c->name, c->hostname);
       return -1;
    }
cp
  len = RSA_size(myself->connection->rsa_key);

  /* Check if the length of the meta key is all right */

  if(strlen(buffer) != len*2)
    {
      syslog(LOG_ERR, _("Possible intruder %s (%s): %s"), c->name, c->hostname, "wrong keylength");
      return -1;
    }

  /* Allocate buffers for the meta key */
cp
  if(!c->inkey)
    c->inkey = xmalloc(len);

  if(!c->inctx)
    c->inctx = xmalloc(sizeof(*c->inctx));

  /* Convert the challenge from hexadecimal back to binary */
cp
  hex2bin(buffer,buffer,len);

  /* Decrypt the meta key */
cp  
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
cp
  /* Check and lookup cipher and digest algorithms */

  if(cipher)
    {
      c->incipher = EVP_get_cipherbynid(cipher);
      if(!c->incipher)
	{
	  syslog(LOG_ERR, _("%s (%s) uses unknown cipher!"), c->name, c->hostname);
	  return -1;
	}

      EVP_DecryptInit(c->inctx, c->incipher,
                      c->inkey + len - c->incipher->key_len,
                      c->inkey + len - c->incipher->key_len - c->incipher->iv_len);

      c->status.decryptin = 1;
    }
  else
    {
      c->incipher = NULL;
    }

  c->inmaclength = maclength;

  if(digest)
    {
      c->indigest = EVP_get_digestbynid(digest);
      if(!c->indigest)
	{
	  syslog(LOG_ERR, _("Node %s (%s) uses unknown digest!"), c->name, c->hostname);
	  return -1;
	}
      
      if(c->inmaclength > c->indigest->md_size || c->inmaclength < 0)
	{
	  syslog(LOG_ERR, _("%s (%s) uses bogus MAC length!"), c->name, c->hostname);
	  return -1;
	}
    }
  else
    {
      c->indigest = NULL;
    }

  c->incompression = compression;

  c->allow_request = CHALLENGE;
cp
  return send_challenge(c);
}

int send_challenge(connection_t *c)
{
  char buffer[MAX_STRING_SIZE];
  int len, x;
cp
  /* CHECKME: what is most reasonable value for len? */

  len = RSA_size(c->rsa_key);

  /* Allocate buffers for the challenge */

  if(!c->hischallenge)
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
  char hash[EVP_MAX_MD_SIZE*2+1];
  EVP_MD_CTX ctx;
cp
  /* Calculate the hash from the challenge we received */

  EVP_DigestInit(&ctx, c->indigest);
  EVP_DigestUpdate(&ctx, c->mychallenge, RSA_size(myself->connection->rsa_key));
  EVP_DigestFinal(&ctx, hash, NULL);

  /* Convert the hash to a hexadecimal formatted string */

  bin2hex(hash,hash,c->indigest->md_size);
  hash[c->indigest->md_size*2] = '\0';

  /* Send the reply */

cp
  return send_request(c, "%d %s", CHAL_REPLY, hash);
}

int chal_reply_h(connection_t *c)
{
  char hishash[MAX_STRING_SIZE];
  char myhash[EVP_MAX_MD_SIZE];
  EVP_MD_CTX ctx;
cp
  if(sscanf(c->buffer, "%*d "MAX_STRING, hishash) != 1)
    {
       syslog(LOG_ERR, _("Got bad %s from %s (%s)"), "CHAL_REPLY", c->name, c->hostname);
       return -1;
    }

  /* Check if the length of the hash is all right */

  if(strlen(hishash) != c->outdigest->md_size*2)
    {
      syslog(LOG_ERR, _("Possible intruder %s (%s): %s"), c->name, c->hostname, _("wrong challenge reply length"));
      return -1;
    }

  /* Convert the hash to binary format */

  hex2bin(hishash, hishash, c->outdigest->md_size);

  /* Calculate the hash from the challenge we sent */

  EVP_DigestInit(&ctx, c->outdigest);
  EVP_DigestUpdate(&ctx, c->hischallenge, RSA_size(c->rsa_key));
  EVP_DigestFinal(&ctx, myhash, NULL);

  /* Verify the incoming hash with the calculated hash */

  if(memcmp(hishash, myhash, c->outdigest->md_size))
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

  int x;
  char *address, *port;
  struct timeval now;
cp
  /* Estimate weight */
  
  gettimeofday(&now, NULL);
  c->estimated_weight = (now.tv_sec - c->start.tv_sec) * 1000 + (now.tv_usec - c->start.tv_usec) / 1000;
  sockaddr2str(&c->address, &address, &port);
  x = send_request(c, "%d %s %s %d %lx", ACK, myport, address, c->estimated_weight, c->options);
  free(address);
  free(port);
cp
  return x;
}

void send_everything(connection_t *c)
{
  avl_node_t *node, *node2;
  node_t *n;
  subnet_t *s;
  edge_t *e;

  /* Send all known subnets */
  
  for(node = node_tree->head; node; node = node->next)
    {
      n = (node_t *)node->data;

      for(node2 = n->subnet_tree->head; node2; node2 = node2->next)
        {
          s = (subnet_t *)node2->data;
          send_add_subnet(c, s);
        }
    }

  /* Send all known edges */

  for(node = edge_tree->head; node; node = node->next)
    {
      e = (edge_t *)node->data;

      if(e == c->edge)
        continue;

      send_add_edge(c, e);
    }
}

int ack_h(connection_t *c)
{
  char myaddress[MAX_STRING_SIZE];
  char hisport[MAX_STRING_SIZE];
  char *hisaddress, *dummy;
  int weight;
  long int options;
  node_t *n;
  connection_t *other;
  avl_node_t *node;
cp
  if(sscanf(c->buffer, "%*d "MAX_STRING" "MAX_STRING" %d %lx", hisport, myaddress, &weight, &options) != 4)
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
      node_add(n);
    }
  else
    {
      if(n->connection)
        {
          /* Oh dear, we already have a connection to this node. */
	  if(debug_lvl >= DEBUG_CONNECTIONS)
            syslog(LOG_DEBUG, _("Established a second connection with %s (%s), closing old connection"), n->name, n->hostname);
          terminate_connection(n->connection, 0);
        }
          
      /* FIXME: check if information in existing node matches that of the other end of this connection */
    }
  
  n->connection = c;
  c->node = n;
  c->options |= options;

  /* Create an edge_t for this connection */

  c->edge = new_edge();
cp  
  c->edge->from.node = myself;
  c->edge->from.udpaddress = str2sockaddr(myaddress, myport);
  c->edge->to.node = n;
  sockaddr2str(&c->address, &hisaddress, &dummy);
  c->edge->to.udpaddress = str2sockaddr(hisaddress, hisport);
  free(hisaddress);
  free(dummy);
  c->edge->weight = (weight + c->estimated_weight) / 2;
  c->edge->connection = c;
  c->edge->options = c->options;
cp
  edge_add(c->edge);

  /* Activate this connection */

  c->allow_request = ALL;
  c->status.active = 1;

  if(debug_lvl >= DEBUG_CONNECTIONS)
    syslog(LOG_NOTICE, _("Connection with %s (%s) activated"), c->name, c->hostname);

cp
  /* Send him everything we know */

  send_everything(c);

  /* Notify others of this connection */

  for(node = connection_tree->head; node; node = node->next)
    {
      other = (connection_t *)node->data;

      if(other->status.active && other != c)
        send_add_edge(other, c->edge);
    }

  /* Run MST and SSSP algorithms */
 
  graph();
cp
  return 0;
}
