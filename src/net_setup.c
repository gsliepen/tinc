/*
    net_setup.c -- Setup.
    Copyright (C) 1998-2002 Ivo Timmermans <itimmermans@bigfoot.com>,
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

    $Id: net_setup.c,v 1.1.2.14 2002/04/01 21:28:39 guus Exp $
*/

#include "config.h"

#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#ifdef HAVE_LINUX
 #include <netinet/ip.h>
 #include <netinet/tcp.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <sys/time.h>
#include <sys/types.h>
#include <syslog.h>
#include <unistd.h>
#include <sys/ioctl.h>
/* SunOS really wants sys/socket.h BEFORE net/if.h,
   and FreeBSD wants these lines below the rest. */
#include <arpa/inet.h>
#include <sys/socket.h>
#include <net/if.h>

#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/rand.h>

#include <utils.h>
#include <xalloc.h>
#include <avl_tree.h>
#include <list.h>

#include "conf.h"
#include "connection.h"
#include "meta.h"
#include "net.h"
#include "netutl.h"
#include "process.h"
#include "protocol.h"
#include "subnet.h"
#include "graph.h"
#include "process.h"
#include "route.h"
#include "device.h"
#include "event.h"

#include "system.h"

char *myport;

int read_rsa_public_key(connection_t *c)
{
  FILE *fp;
  char *fname;
  char *key;
cp
  if(!c->rsa_key)
    c->rsa_key = RSA_new();

  /* First, check for simple PublicKey statement */

  if(get_config_string(lookup_config(c->config_tree, "PublicKey"), &key))
    {
      BN_hex2bn(&c->rsa_key->n, key);
      BN_hex2bn(&c->rsa_key->e, "FFFF");
      free(key);
      return 0;
    }

  /* Else, check for PublicKeyFile statement and read it */

  if(get_config_string(lookup_config(c->config_tree, "PublicKeyFile"), &fname))
    {
      if(is_safe_path(fname))
        {
          if((fp = fopen(fname, "r")) == NULL)
            {
              syslog(LOG_ERR, _("Error reading RSA public key file `%s': %s"),
                     fname, strerror(errno));
              free(fname);
              return -1;
            }
          free(fname);
          c->rsa_key = PEM_read_RSAPublicKey(fp, &c->rsa_key, NULL, NULL);
          fclose(fp);
          if(!c->rsa_key)
            {
              syslog(LOG_ERR, _("Reading RSA public key file `%s' failed: %s"),
                     fname, strerror(errno));
              return -1;
            }
          return 0;
        }
      else
        {
          free(fname);
          return -1;
        }
    }

  /* Else, check if a harnessed public key is in the config file */

  asprintf(&fname, "%s/hosts/%s", confbase, c->name);
  if((fp = fopen(fname, "r")))
    {
      c->rsa_key = PEM_read_RSAPublicKey(fp, &c->rsa_key, NULL, NULL);
      fclose(fp);
    }

  free(fname);

  if(c->rsa_key)
    return 0;
  else
    {
      syslog(LOG_ERR, _("No public key for %s specified!"), c->name);
      return -1;
    }
}

int read_rsa_private_key(void)
{
  FILE *fp;
  char *fname, *key;
cp
  if(get_config_string(lookup_config(config_tree, "PrivateKey"), &key))
    {
      myself->connection->rsa_key = RSA_new();
      BN_hex2bn(&myself->connection->rsa_key->d, key);
      BN_hex2bn(&myself->connection->rsa_key->e, "FFFF");
      free(key);
      return 0;
    }

  if(!get_config_string(lookup_config(config_tree, "PrivateKeyFile"), &fname))
    asprintf(&fname, "%s/rsa_key.priv", confbase);

  if(is_safe_path(fname))
    {
      if((fp = fopen(fname, "r")) == NULL)
        {
          syslog(LOG_ERR, _("Error reading RSA private key file `%s': %s"),
                 fname, strerror(errno));
          free(fname);
          return -1;
        }
      free(fname);
      myself->connection->rsa_key = PEM_read_RSAPrivateKey(fp, NULL, NULL, NULL);
      fclose(fp);
      if(!myself->connection->rsa_key)
        {
          syslog(LOG_ERR, _("Reading RSA private key file `%s' failed: %s"),
                 fname, strerror(errno));
          return -1;
        }
      return 0;
    }

  free(fname);
  return -1;
}

/*
  Configure node_t myself and set up the local sockets (listen only)
*/
int setup_myself(void)
{
  config_t *cfg;
  subnet_t *subnet;
  char *name, *hostname, *mode, *afname, *cipher, *digest;
  struct addrinfo hint, *ai, *aip;
  int choice, err;
cp
  myself = new_node();
  myself->connection = new_connection();
  init_configuration(&myself->connection->config_tree);

  asprintf(&myself->hostname, _("MYSELF"));
  asprintf(&myself->connection->hostname, _("MYSELF"));

  myself->connection->options = 0;
  myself->connection->protocol_version = PROT_CURRENT;

  if(!get_config_string(lookup_config(config_tree, "Name"), &name)) /* Not acceptable */
    {
      syslog(LOG_ERR, _("Name for tinc daemon required!"));
      return -1;
    }

  if(check_id(name))
    {
      syslog(LOG_ERR, _("Invalid name for myself!"));
      free(name);
      return -1;
    }

  myself->name = name;
  myself->connection->name = xstrdup(name);

cp
  if(read_rsa_private_key())
    return -1;

  if(read_connection_config(myself->connection))
    {
      syslog(LOG_ERR, _("Cannot open host configuration file for myself!"));
      return -1;
    }

  if(read_rsa_public_key(myself->connection))
    return -1;
cp

  if(!get_config_string(lookup_config(myself->connection->config_tree, "Port"), &myport))
    asprintf(&myport, "655");

/* Read in all the subnets specified in the host configuration file */

  cfg = lookup_config(myself->connection->config_tree, "Subnet");

  while(cfg)
    {
      if(!get_config_subnet(cfg, &subnet))
        return -1;

      subnet_add(myself, subnet);

      cfg = lookup_config_next(myself->connection->config_tree, cfg);
    }

cp
  /* Check some options */

  if(get_config_bool(lookup_config(config_tree, "IndirectData"), &choice))
    if(choice)
      myself->options |= OPTION_INDIRECT;

  if(get_config_bool(lookup_config(config_tree, "TCPOnly"), &choice))
    if(choice)
      myself->options |= OPTION_TCPONLY;

  if(get_config_bool(lookup_config(myself->connection->config_tree, "IndirectData"), &choice))
    if(choice)
      myself->options |= OPTION_INDIRECT;

  if(get_config_bool(lookup_config(myself->connection->config_tree, "TCPOnly"), &choice))
    if(choice)
      myself->options |= OPTION_TCPONLY;

  if(myself->options & OPTION_TCPONLY)
    myself->options |= OPTION_INDIRECT;

  if(get_config_string(lookup_config(config_tree, "Mode"), &mode))
    {
      if(!strcasecmp(mode, "router"))
        routing_mode = RMODE_ROUTER;
      else if (!strcasecmp(mode, "switch"))
        routing_mode = RMODE_SWITCH;
      else if (!strcasecmp(mode, "hub"))
        routing_mode = RMODE_HUB;
      else
        {
          syslog(LOG_ERR, _("Invalid routing mode!"));
          return -1;
        }
      free(mode);
    }
  else
    routing_mode = RMODE_ROUTER;

  get_config_bool(lookup_config(config_tree, "PriorityInheritance"), &priorityinheritance);
#if !defined(SOL_IP) || !defined(IP_TOS)
  if(priorityinheritance)
    syslog(LOG_WARNING, _("PriorityInheritance not supported on this platform"));
#endif

  if(!get_config_int(lookup_config(config_tree, "MACExpire"), &macexpire))
    macexpire= 600;

  if(get_config_int(lookup_config(myself->connection->config_tree, "MaxTimeout"), &maxtimeout))
    {
      if(maxtimeout <= 0)
        {
          syslog(LOG_ERR, _("Bogus maximum timeout!"));
          return -1;
        }
    }
  else
    maxtimeout = 900;

  if(get_config_string(lookup_config(config_tree, "AddressFamily"), &afname))
    {
      if(!strcasecmp(afname, "IPv4"))
        addressfamily = AF_INET;
      else if (!strcasecmp(afname, "IPv6"))
        addressfamily = AF_INET6;
      else if (!strcasecmp(afname, "any"))
        addressfamily = AF_UNSPEC;
      else
        {
          syslog(LOG_ERR, _("Invalid address family!"));
          return -1;
        }
      free(afname);
    }
  else
    addressfamily = AF_INET;

  get_config_bool(lookup_config(config_tree, "Hostnames"), &hostnames);
cp
  /* Generate packet encryption key */

  if(get_config_string(lookup_config(myself->connection->config_tree, "Cipher"), &cipher))
    {
      if(!strcasecmp(cipher, "none"))
        {
          myself->cipher = NULL;
        }
      else
        {
          if(!(myself->cipher = EVP_get_cipherbyname(cipher)))
            {
              syslog(LOG_ERR, _("Unrecognized cipher type!"));
              return -1;
            }
        }
    }
  else
    myself->cipher = EVP_bf_cbc();

  if(myself->cipher)
    myself->keylength = myself->cipher->key_len + myself->cipher->iv_len;
  else
    myself->keylength = 1;

  myself->connection->outcipher = EVP_bf_ofb();

  myself->key = (char *)xmalloc(myself->keylength);
  RAND_pseudo_bytes(myself->key, myself->keylength);

  if(!get_config_int(lookup_config(config_tree, "KeyExpire"), &keylifetime))
    keylifetime = 3600;

  keyexpires = now + keylifetime;

  /* Check if we want to use message authentication codes... */

  if(get_config_string(lookup_config(myself->connection->config_tree, "Digest"), &digest))
    {
      if(!strcasecmp(digest, "none"))
        {
          myself->digest = NULL;
        }
      else
        {
          if(!(myself->digest = EVP_get_digestbyname(digest)))
            {
              syslog(LOG_ERR, _("Unrecognized digest type!"));
              return -1;
            }
        }
    }
  else
    myself->digest = EVP_sha1();

  myself->connection->outdigest = EVP_sha1();

  if(get_config_int(lookup_config(myself->connection->config_tree, "MACLength"), &myself->maclength))
    {
      if(myself->digest)
        {
          if(myself->maclength > myself->digest->md_size)
            {
              syslog(LOG_ERR, _("MAC length exceeds size of digest!"));
              return -1;
            }
          else if (myself->maclength < 0)
            {
              syslog(LOG_ERR, _("Bogus MAC length!"));
              return -1;
            }
        }
    }
  else
    myself->maclength = 4;

  myself->connection->outmaclength = 0;

  /* Compression */

  if(get_config_int(lookup_config(myself->connection->config_tree, "Compression"), &myself->compression))
    {
      if(myself->compression < 0 || myself->compression > 9)
        {
          syslog(LOG_ERR, _("Bogus compression level!"));
          return -1;
        }
    }
  else
    myself->compression = 0;

  myself->connection->outcompression = 0;
cp
  /* Done */

  myself->nexthop = myself;
  myself->via = myself;
  myself->status.active = 1;
  myself->status.reachable = 1;
  node_add(myself);

  graph();

cp
  /* Open sockets */
  
  memset(&hint, 0, sizeof(hint));
  
  hint.ai_family = addressfamily;
  hint.ai_socktype = SOCK_STREAM;
  hint.ai_protocol = IPPROTO_TCP;
  hint.ai_flags = AI_PASSIVE;

  if((err = getaddrinfo(NULL, myport, &hint, &ai)) || !ai)
    {
      syslog(LOG_ERR, _("System call `%s' failed: %s"), "getaddrinfo", gai_strerror(err));
      return -1;
    }

  for(aip = ai; aip; aip = aip->ai_next)
    {
      if((listen_socket[listen_sockets].tcp = setup_listen_socket((sockaddr_t *)aip->ai_addr)) < 0)
        continue;

      if((listen_socket[listen_sockets].udp = setup_vpn_in_socket((sockaddr_t *)aip->ai_addr)) < 0)
        continue;

      if(debug_lvl >= DEBUG_CONNECTIONS)
        {
	  hostname = sockaddr2hostname((sockaddr_t *)aip->ai_addr);
	  syslog(LOG_NOTICE, _("Listening on %s"), hostname);
	  free(hostname);
	}

      listen_socket[listen_sockets].sa.sa = *aip->ai_addr;
      listen_sockets++;
    }

  freeaddrinfo(ai);

  if(listen_sockets)
    syslog(LOG_NOTICE, _("Ready"));
  else
    {
      syslog(LOG_ERR, _("Unable to create any listening socket!"));
      return -1;
    }
cp
  return 0;
}

/*
  setup all initial network connections
*/
int setup_network_connections(void)
{
cp
  now = time(NULL);

  init_connections();
  init_subnets();
  init_nodes();
  init_edges();
  init_events();
  init_requests();

  if(get_config_int(lookup_config(config_tree, "PingTimeout"), &pingtimeout))
    {
      if(pingtimeout < 1)
        {
          pingtimeout = 86400;
        }
    }
  else
    pingtimeout = 60;

  if(setup_device() < 0)
    return -1;

  /* Run tinc-up script to further initialize the tap interface */
  execute_script("tinc-up");

  if(setup_myself() < 0)
    return -1;

  try_outgoing_connections();
cp
  return 0;
}

/*
  close all open network connections
*/
void close_network_connections(void)
{
  avl_node_t *node, *next;
  connection_t *c;
  int i;
cp
  for(node = connection_tree->head; node; node = next)
    {
      next = node->next;
      c = (connection_t *)node->data;
      if(c->outgoing)
        free(c->outgoing->name), free(c->outgoing), c->outgoing = NULL;
      terminate_connection(c, 0);
    }

  if(myself && myself->connection)
    terminate_connection(myself->connection, 0);

  for(i = 0; i < listen_sockets; i++)
    {
      close(listen_socket[i].tcp);
      close(listen_socket[i].udp);
    }

  exit_requests();
  exit_events();
  exit_edges();
  exit_subnets();
  exit_nodes();
  exit_connections();

  execute_script("tinc-down");

  close_device();
cp
  return;
}
