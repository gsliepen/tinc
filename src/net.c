/*
    net.c -- most of the network code
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

    $Id: net.c,v 1.35.4.155 2002/02/12 14:36:45 guus Exp $
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

#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/hmac.h>

#ifndef HAVE_RAND_PSEUDO_BYTES
#define RAND_pseudo_bytes RAND_bytes
#endif

#include <zlib.h>

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

int maxtimeout = 900;
int seconds_till_retry = 5;

int tcp_socket = -1;
int udp_socket = -1;

int keylifetime = 0;
int keyexpires = 0;

int do_prune = 0;
int do_purge = 0;
int sighup = 0;
int sigalrm = 0;

#define MAX_SEQNO 1073741824

/* VPN packet I/O */

void receive_udppacket(node_t *n, vpn_packet_t *inpkt)
{
  vpn_packet_t pkt1, pkt2;
  vpn_packet_t *pkt[] = {&pkt1, &pkt2, &pkt1, &pkt2};
  int nextpkt = 0;
  vpn_packet_t *outpkt = pkt[0];
  int outlen, outpad;
  long int complen = MTU + 12;
  EVP_CIPHER_CTX ctx;
  char hmac[EVP_MAX_MD_SIZE];
cp
  /* Check the message authentication code */

  if(myself->digest && myself->maclength)
    {
      inpkt->len -= myself->maclength;
      HMAC(myself->digest, myself->key, myself->keylength, (char *)&inpkt->seqno, inpkt->len, hmac, NULL);
      if(memcmp(hmac, (char *)&inpkt->seqno + inpkt->len, myself->maclength))
	{
	  syslog(LOG_DEBUG, _("Got unauthenticated packet from %s (%s)"), n->name, n->hostname);
	  return;
	}
    }

  /* Decrypt the packet */

  if(myself->cipher)
  {
    outpkt = pkt[nextpkt++];

    EVP_DecryptInit(&ctx, myself->cipher, myself->key, myself->key + myself->cipher->key_len);
    EVP_DecryptUpdate(&ctx, (char *)&outpkt->seqno, &outlen, (char *)&inpkt->seqno, inpkt->len);
    EVP_DecryptFinal(&ctx, (char *)&outpkt->seqno + outlen, &outpad);

    outpkt->len = outlen + outpad;
    inpkt = outpkt;
  }

  /* Check the sequence number */

  inpkt->len -= sizeof(inpkt->seqno);
  inpkt->seqno = ntohl(inpkt->seqno);

  if(inpkt->seqno <= n->received_seqno)
  {
    syslog(LOG_DEBUG, _("Got late or replayed packet from %s (%s), seqno %d"), n->name, n->hostname, inpkt->seqno);
    return;
  }
  
  n->received_seqno = inpkt->seqno;

  if(n->received_seqno > MAX_SEQNO)
    keyexpires = 0;

  /* Decompress the packet */
  
  if(myself->compression)
  {
    outpkt = pkt[nextpkt++];

    if(uncompress(outpkt->data, &complen, inpkt->data, inpkt->len) != Z_OK)
    {
      syslog(LOG_ERR, _("Error while uncompressing packet from %s (%s)"), n->name, n->hostname);
      return;
    }
    
    outpkt->len = complen;
    inpkt = outpkt;
  }

  receive_packet(n, inpkt);
cp
}

void receive_tcppacket(connection_t *c, char *buffer, int len)
{
  vpn_packet_t outpkt;
cp
  outpkt.len = len;
  memcpy(outpkt.data, buffer, len);

  receive_packet(c->node, &outpkt);
cp
}

void receive_packet(node_t *n, vpn_packet_t *packet)
{
cp
  if(debug_lvl >= DEBUG_TRAFFIC)
    syslog(LOG_DEBUG, _("Received packet of %d bytes from %s (%s)"), packet->len, n->name, n->hostname);

  route_incoming(n, packet);
cp
}

void send_udppacket(node_t *n, vpn_packet_t *inpkt)
{
  vpn_packet_t pkt1, pkt2;
  vpn_packet_t *pkt[] = {&pkt1, &pkt2, &pkt1, &pkt2};
  int nextpkt = 0;
  vpn_packet_t *outpkt;
  int outlen, outpad;
  long int complen = MTU + 12;
  EVP_CIPHER_CTX ctx;
  struct sockaddr_in to;
  socklen_t tolen = sizeof(to);
  vpn_packet_t *copy;
cp
  if(!n->status.validkey)
    {
      if(debug_lvl >= DEBUG_TRAFFIC)
	syslog(LOG_INFO, _("No valid key known yet for %s (%s), queueing packet"),
	       n->name, n->hostname);

      /* Since packet is on the stack of handle_tap_input(),
         we have to make a copy of it first. */

      copy = xmalloc(sizeof(vpn_packet_t));
      memcpy(copy, inpkt, sizeof(vpn_packet_t));

      list_insert_tail(n->queue, copy);

      if(!n->status.waitingforkey)
	send_req_key(n->nexthop->connection, myself, n);

      return;
    }

  /* Compress the packet */

  if(n->compression)
  {
    outpkt = pkt[nextpkt++];

    if(compress2(outpkt->data, &complen, inpkt->data, inpkt->len, n->compression) != Z_OK)
    {
      syslog(LOG_ERR, _("Error while compressing packet to %s (%s)"), n->name, n->hostname);
      return;
    }
    
    outpkt->len = complen;
    inpkt = outpkt;
  }

  /* Add sequence number */

  inpkt->seqno = htonl(++(n->sent_seqno));
  inpkt->len += sizeof(inpkt->seqno);

  /* Encrypt the packet */

  if(n->cipher)
  {
    outpkt = pkt[nextpkt++];

    EVP_EncryptInit(&ctx, n->cipher, n->key, n->key + n->cipher->key_len);
    EVP_EncryptUpdate(&ctx, (char *)&outpkt->seqno, &outlen, (char *)&inpkt->seqno, inpkt->len);
    EVP_EncryptFinal(&ctx, (char *)&outpkt->seqno + outlen, &outpad);

    outpkt->len = outlen + outpad;
    inpkt = outpkt;
  }

  /* Add the message authentication code */

  if(n->digest && n->maclength)
    {
      HMAC(n->digest, n->key, n->keylength, (char *)&inpkt->seqno, inpkt->len, (char *)&inpkt->seqno + inpkt->len, &outlen);
      inpkt->len += n->maclength;
    }

  /* Send the packet */

  to.sin_family = AF_INET;
  to.sin_addr.s_addr = htonl(n->address);
  to.sin_port = htons(n->port);

  if((sendto(udp_socket, (char *)&inpkt->seqno, inpkt->len, 0, (const struct sockaddr *)&to, tolen)) < 0)
    {
      syslog(LOG_ERR, _("Error sending packet to %s (%s): %m"),
             n->name, n->hostname);
      return;
    }
cp
}

/*
  send a packet to the given vpn ip.
*/
void send_packet(node_t *n, vpn_packet_t *packet)
{
  node_t *via;
cp
  if(debug_lvl >= DEBUG_TRAFFIC)
    syslog(LOG_ERR, _("Sending packet of %d bytes to %s (%s)"),
           packet->len, n->name, n->hostname);

  if(n == myself)
    {
      if(debug_lvl >= DEBUG_TRAFFIC)
        {
          syslog(LOG_NOTICE, _("Packet is looping back to us!"));
        }

      return;
    }
 
  if(!n->status.reachable)
    {
      if(debug_lvl >= DEBUG_TRAFFIC)
	syslog(LOG_INFO, _("Node %s (%s) is not reachable"),
	       n->name, n->hostname);
      return;
    }

  via = (n->via == myself)?n->nexthop:n->via;

  if(via != n && debug_lvl >= DEBUG_TRAFFIC)
    syslog(LOG_ERR, _("Sending packet to %s via %s (%s)"),
           n->name, via->name, n->via->hostname);

  if((myself->options | via->options) & OPTION_TCPONLY)
    {
      if(send_tcppacket(via->connection, packet))
        terminate_connection(via->connection, 1);
    }
  else
    send_udppacket(via, packet);
}

/* Broadcast a packet using the minimum spanning tree */

void broadcast_packet(node_t *from, vpn_packet_t *packet)
{
  avl_node_t *node;
  connection_t *c;
cp
  if(debug_lvl >= DEBUG_TRAFFIC)
    syslog(LOG_INFO, _("Broadcasting packet of %d bytes from %s (%s)"),
	   packet->len, from->name, from->hostname);

  for(node = connection_tree->head; node; node = node->next)
    {
      c = (connection_t *)node->data;
      if(c->status.active && c->status.mst && c != from->nexthop->connection)
        send_packet(c->node, packet);
    }
cp
}

void flush_queue(node_t *n)
{
  list_node_t *node, *next;
cp
  if(debug_lvl >= DEBUG_TRAFFIC)
    syslog(LOG_INFO, _("Flushing queue for %s (%s)"), n->name, n->hostname);

  for(node = n->queue->head; node; node = next)
    {
      next = node->next;
      send_udppacket(n, (vpn_packet_t *)node->data);
      list_delete_node(n->queue, node);
    }
cp
}

/* Setup sockets */

int setup_listen_socket(port_t port)
{
  int nfd, flags;
  struct sockaddr_in a;
  int option;
  ipv4_t *address;
#ifdef HAVE_LINUX
  char *interface;
#endif
cp
  if((nfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0)
    {
      syslog(LOG_ERR, _("Creating metasocket failed: %m"));
      return -1;
    }

  flags = fcntl(nfd, F_GETFL);
  if(fcntl(nfd, F_SETFL, flags | O_NONBLOCK) < 0)
    {
      close(nfd);
      syslog(LOG_ERR, _("System call `%s' failed: %m"),
	     "fcntl");
      return -1;
    }

  /* Optimize TCP settings */

  option = 1;
  setsockopt(nfd, SOL_SOCKET, SO_REUSEADDR, &option, sizeof(option));
  setsockopt(nfd, SOL_SOCKET, SO_KEEPALIVE, &option, sizeof(option));
#ifdef HAVE_LINUX
  setsockopt(nfd, SOL_TCP, TCP_NODELAY, &option, sizeof(option));

  option = IPTOS_LOWDELAY;
  setsockopt(nfd, SOL_IP, IP_TOS, &option, sizeof(option));

  if(get_config_string(lookup_config(config_tree, "BindToInterface"), &interface))
    if(setsockopt(nfd, SOL_SOCKET, SO_BINDTODEVICE, interface, strlen(interface)))
      {
        close(nfd);
        syslog(LOG_ERR, _("Can't bind to interface %s: %m"), interface);
        return -1;
      }
#endif

  memset(&a, 0, sizeof(a));
  a.sin_family = AF_INET;
  a.sin_addr.s_addr = htonl(INADDR_ANY);
  a.sin_port = htons(port);

  if(get_config_address(lookup_config(config_tree, "BindToAddress"), &address))
    {
      a.sin_addr.s_addr = htonl(*address);
      free(address);
    }

  if(bind(nfd, (struct sockaddr *)&a, sizeof(struct sockaddr)))
    {
      close(nfd);
      syslog(LOG_ERR, _("Can't bind to port %hd/tcp: %m"), port);
      return -1;
    }

  if(listen(nfd, 3))
    {
      close(nfd);
      syslog(LOG_ERR, _("System call `%s' failed: %m"),
	     "listen");
      return -1;
    }
cp
  return nfd;
}

int setup_vpn_in_socket(port_t port)
{
  int nfd, flags;
  struct sockaddr_in a;
  const int one = 1;
cp
  if((nfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0)
    {
      close(nfd);
      syslog(LOG_ERR, _("Creating socket failed: %m"));
      return -1;
    }

  setsockopt(nfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

  flags = fcntl(nfd, F_GETFL);
  if(fcntl(nfd, F_SETFL, flags | O_NONBLOCK) < 0)
    {
      close(nfd);
      syslog(LOG_ERR, _("System call `%s' failed: %m"),
	     "fcntl");
      return -1;
    }

  memset(&a, 0, sizeof(a));
  a.sin_family = AF_INET;
  a.sin_port = htons(port);
  a.sin_addr.s_addr = htonl(INADDR_ANY);

  if(bind(nfd, (struct sockaddr *)&a, sizeof(struct sockaddr)))
    {
      close(nfd);
      syslog(LOG_ERR, _("Can't bind to port %hd/udp: %m"), port);
      return -1;
    }
cp
  return nfd;
}

void retry_outgoing(outgoing_t *outgoing)
{
  event_t *event;
cp
  outgoing->timeout += 5;
  if(outgoing->timeout > maxtimeout)
    outgoing->timeout = maxtimeout;

  event = new_event();
  event->handler = (event_handler_t)setup_outgoing_connection;
  event->time = time(NULL) + outgoing->timeout;
  event->data = outgoing;
  event_add(event);

  if(debug_lvl >= DEBUG_CONNECTIONS)
    syslog(LOG_NOTICE, _("Trying to re-establish outgoing connection in %d seconds"), outgoing->timeout);
cp
}

int setup_outgoing_socket(connection_t *c)
{
  int flags;
  struct sockaddr_in a;
cp
  if(debug_lvl >= DEBUG_CONNECTIONS)
    syslog(LOG_INFO, _("Trying to connect to %s (%s)"), c->name, c->hostname);

  c->socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

  if(c->socket == -1)
    {
      syslog(LOG_ERR, _("Creating socket for %s port %d failed: %m"),
             c->hostname, c->port);
      return -1;
    }

  /* Bind first to get a fix on our source port???

  a.sin_family = AF_INET;
  a.sin_port = htons(0);
  a.sin_addr.s_addr = htonl(INADDR_ANY);

  if(bind(c->socket, (struct sockaddr *)&a, sizeof(struct sockaddr)))
    {
      close(c->socket);
      syslog(LOG_ERR, _("System call `%s' failed: %m"), "bind");
      return -1;
    }

  */

  /* Optimize TCP settings?

  option = 1;
  setsockopt(c->socket, SOL_SOCKET, SO_KEEPALIVE, &option, sizeof(option));
#ifdef HAVE_LINUX
  setsockopt(c->socket, SOL_TCP, TCP_NODELAY, &option, sizeof(option));

  option = IPTOS_LOWDELAY;
  setsockopt(c->socket, SOL_IP, IP_TOS, &option, sizeof(option));
#endif

  */

  /* Connect */

  a.sin_family = AF_INET;
  a.sin_port = htons(c->port);
  a.sin_addr.s_addr = htonl(c->address);

  if(connect(c->socket, (struct sockaddr *)&a, sizeof(a)) == -1)
    {
      close(c->socket);
      syslog(LOG_ERR, _("%s port %hd: %m"), c->hostname, c->port);
      return -1;
    }

  flags = fcntl(c->socket, F_GETFL);

  if(fcntl(c->socket, F_SETFL, flags | O_NONBLOCK) < 0)
    {
      close(c->socket);
      syslog(LOG_ERR, _("fcntl for %s port %d: %m"),
             c->hostname, c->port);
      return -1;
    }

  if(debug_lvl >= DEBUG_CONNECTIONS)
    syslog(LOG_INFO, _("Connected to %s port %hd"),
         c->hostname, c->port);
cp
  return 0;
}

void setup_outgoing_connection(outgoing_t *outgoing)
{
  connection_t *c;
  node_t *n;
  struct hostent *h;
cp
  n = lookup_node(outgoing->name);
  
  if(n)
    if(n->connection)
      {
        if(debug_lvl >= DEBUG_CONNECTIONS)       
          syslog(LOG_INFO, _("Already connected to %s"), outgoing->name);
        n->connection->outgoing = outgoing;
        return;
      }

  c = new_connection();
  c->name = xstrdup(outgoing->name);

  init_configuration(&c->config_tree);
  read_connection_config(c);
  
  if(!get_config_string(lookup_config(c->config_tree, "Address"), &c->hostname))
    {
      syslog(LOG_ERR, _("No address specified for %s"), c->name);
      free_connection(c);
      free(outgoing->name);
      free(outgoing);
      return;
    }

  if(!get_config_port(lookup_config(c->config_tree, "Port"), &c->port))
    c->port = 655;

  if(!(h = gethostbyname(c->hostname)))
    {
      syslog(LOG_ERR, _("Error looking up `%s': %m"), c->hostname);
      free_connection(c);
      retry_outgoing(outgoing);
      return;
    }

  c->address = ntohl(*((ipv4_t*)(h->h_addr_list[0])));
  c->hostname = hostlookup(htonl(c->address));

  if(setup_outgoing_socket(c) < 0)
    {
      syslog(LOG_ERR, _("Could not set up a meta connection to %s (%s)"),
             c->name, c->hostname);
      retry_outgoing(outgoing);
      return;
    }

  c->outgoing = outgoing;
  c->last_ping_time = time(NULL);

  connection_add(c);

  send_id(c);
cp
}

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
              syslog(LOG_ERR, _("Error reading RSA public key file `%s': %m"),
	             fname);
              free(fname);
              return -1;
            }
          free(fname);
          c->rsa_key = PEM_read_RSAPublicKey(fp, &c->rsa_key, NULL, NULL);
          fclose(fp);
          if(!c->rsa_key)
            {
              syslog(LOG_ERR, _("Reading RSA public key file `%s' failed: %m"),
	             fname);
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
          syslog(LOG_ERR, _("Error reading RSA private key file `%s': %m"),
	         fname);
          free(fname);
          return -1;
        }
      free(fname);
      myself->connection->rsa_key = PEM_read_RSAPrivateKey(fp, NULL, NULL, NULL);
      fclose(fp);
      if(!myself->connection->rsa_key)
        {
          syslog(LOG_ERR, _("Reading RSA private key file `%s' failed: %m"),
	         fname);
          return -1;
        }
      return 0;
    }

  free(fname);
  return -1;
}

int check_rsa_key(RSA *rsa_key)
{
  char *test1, *test2, *test3;
cp
  if(rsa_key->p && rsa_key->q)
    {
      if(RSA_check_key(rsa_key) != 1)
	  return -1;
    }
  else
    {
      test1 = xmalloc(RSA_size(rsa_key));
      test2 = xmalloc(RSA_size(rsa_key));
      test3 = xmalloc(RSA_size(rsa_key));

      if(RSA_public_encrypt(RSA_size(rsa_key), test1, test2, rsa_key, RSA_NO_PADDING) != RSA_size(rsa_key))
	  return -1;

      if(RSA_private_decrypt(RSA_size(rsa_key), test2, test3, rsa_key, RSA_NO_PADDING) != RSA_size(rsa_key))
	  return -1;

      if(memcmp(test1, test3, RSA_size(rsa_key)))
	  return -1;
    }
cp
  return 0;
}

/*
  Configure node_t myself and set up the local sockets (listen only)
*/
int setup_myself(void)
{
  config_t *cfg;
  subnet_t *subnet;
  char *name, *mode, *cipher, *digest;
  int choice;
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

  if(check_rsa_key(myself->connection->rsa_key))
    {
      syslog(LOG_ERR, _("Invalid public/private keypair!"));
      return -1;
    }

  if(!get_config_port(lookup_config(myself->connection->config_tree, "Port"), &myself->port))
    myself->port = 655;

  myself->connection->port = myself->port;

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
    }
  else
    routing_mode = RMODE_ROUTER;

cp
  /* Open sockets */
  
  if((tcp_socket = setup_listen_socket(myself->port)) < 0)
    {
      syslog(LOG_ERR, _("Unable to set up a listening TCP socket!"));
      return -1;
    }

  if((udp_socket = setup_vpn_in_socket(myself->port)) < 0)
    {
      syslog(LOG_ERR, _("Unable to set up a listening UDP socket!"));
      return -1;
    }
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

  myself->key = (char *)xmalloc(myself->keylength);
  RAND_pseudo_bytes(myself->key, myself->keylength);

  if(!get_config_int(lookup_config(config_tree, "KeyExpire"), &keylifetime))
    keylifetime = 3600;

  keyexpires = time(NULL) + keylifetime;

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
cp
  /* Done */

  myself->nexthop = myself;
  myself->via = myself;
  myself->status.active = 1;
  node_add(myself);

  graph();

  syslog(LOG_NOTICE, _("Ready: listening on port %hd"), myself->port);
cp
  return 0;
}

/*
  setup all initial network connections
*/
int setup_network_connections(void)
{
cp
  init_connections();
  init_subnets();
  init_nodes();
  init_edges();
  init_events();

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
cp
  for(node = connection_tree->head; node; node = next)
    {
      next = node->next;
      c = (connection_t *)node->data;
      if(c->outgoing)
        free(c->outgoing->name), free(c->outgoing);
      terminate_connection(c, 0);
    }

  if(myself && myself->connection)
    terminate_connection(myself->connection, 0);

  close(udp_socket);
  close(tcp_socket);

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

/*
  handle an incoming tcp connect call and open
  a connection to it.
*/
connection_t *create_new_connection(int sfd)
{
  connection_t *c;
  struct sockaddr_in ci;
  int len = sizeof(ci);
cp
  c = new_connection();

  if(getpeername(sfd, (struct sockaddr *) &ci, (socklen_t *) &len) < 0)
    {
      syslog(LOG_ERR, _("System call `%s' failed: %m"),
	     "getpeername");
      close(sfd);
      return NULL;
    }

  c->address = ntohl(ci.sin_addr.s_addr);
  c->hostname = hostlookup(ci.sin_addr.s_addr);
  c->port = htons(ci.sin_port);
  c->socket = sfd;
  c->last_ping_time = time(NULL);

  if(debug_lvl >= DEBUG_CONNECTIONS)
    syslog(LOG_NOTICE, _("Connection from %s port %d"),
         c->hostname, c->port);

  c->allow_request = ID;
cp
  return c;
}

/*
  put all file descriptors in an fd_set array
*/
void build_fdset(fd_set *fs)
{
  avl_node_t *node;
  connection_t *c;
cp
  FD_ZERO(fs);

  for(node = connection_tree->head; node; node = node->next)
    {
      c = (connection_t *)node->data;
      FD_SET(c->socket, fs);
    }

  FD_SET(tcp_socket, fs);
  FD_SET(udp_socket, fs);
  FD_SET(device_fd, fs);
cp
}

/*
  receive incoming data from the listening
  udp socket and write it to the ethertap
  device after being decrypted
*/
void handle_incoming_vpn_data(void)
{
  vpn_packet_t pkt;
  int x, l = sizeof(x);
  struct sockaddr_in from;
  socklen_t fromlen = sizeof(from);
  node_t *n;
cp
  if(getsockopt(udp_socket, SOL_SOCKET, SO_ERROR, &x, &l) < 0)
    {
      syslog(LOG_ERR, _("This is a bug: %s:%d: %d:%m"),
	     __FILE__, __LINE__, udp_socket);
      return;
    }
  if(x)
    {
      syslog(LOG_ERR, _("Incoming data socket error: %s"), strerror(x));
      return;
    }

  if((pkt.len = recvfrom(udp_socket, (char *)&pkt.seqno, MAXSIZE, 0, (struct sockaddr *)&from, &fromlen)) <= 0)
    {
      syslog(LOG_ERR, _("Receiving packet failed: %m"));
      return;
    }

  n = lookup_node_udp(ntohl(from.sin_addr.s_addr), ntohs(from.sin_port));

  if(!n)
    {
      syslog(LOG_WARNING, _("Received UDP packet on port %hd from unknown source %x:%hd"), myself->port, ntohl(from.sin_addr.s_addr), ntohs(from.sin_port));
      return;
    }

/*
  if(n->connection)
    n->connection->last_ping_time = time(NULL);
*/
  receive_udppacket(n, &pkt);
cp
}

/* Purge edges and subnets of unreachable nodes. Use carefully. */

void purge(void)
{
  avl_node_t *nnode, *nnext, *enode, *enext, *snode, *snext, *cnode;
  node_t *n;
  edge_t *e;
  subnet_t *s;
  connection_t *c;
cp
  if(debug_lvl >= DEBUG_PROTOCOL)
    syslog(LOG_DEBUG, _("Purging unreachable nodes"));

  for(nnode = node_tree->head; nnode; nnode = nnext)
  {
    nnext = nnode->next;
    n = (node_t *)nnode->data;

    if(!n->status.reachable)
    {
      if(debug_lvl >= DEBUG_SCARY_THINGS)
        syslog(LOG_DEBUG, _("Purging node %s (%s)"), n->name, n->hostname);

      for(snode = n->subnet_tree->head; snode; snode = snext)
      {
        snext = snode->next;
	s = (subnet_t *)snode->data;
	
	for(cnode = connection_tree->head; cnode; cnode = cnode->next)
	{
	  c = (connection_t *)cnode->data;
	  if(c->status.active)
	    send_del_subnet(c, s);
	}
	
	subnet_del(n, s);
      }
	
      for(enode = n->edge_tree->head; enode; enode = enext)
      {
        enext = enode->next;
	e = (edge_t *)enode->data;
	
	for(cnode = connection_tree->head; cnode; cnode = cnode->next)
	{
	  c = (connection_t *)cnode->data;
	  if(c->status.active)
	    send_del_edge(c, e);
	}
	
	edge_del(e);
      }

      node_del(n);
    }
  }	
cp
}

/*
  Terminate a connection:
  - Close the socket
  - Remove associated edge and tell other connections about it if report = 1
  - Check if we need to retry making an outgoing connection
  - Deactivate the host
*/
void terminate_connection(connection_t *c, int report)
{
  avl_node_t *node;
  connection_t *other;
cp
  if(c->status.remove)
    return;
  
  if(debug_lvl >= DEBUG_CONNECTIONS)
    syslog(LOG_NOTICE, _("Closing connection with %s (%s)"),
           c->name, c->hostname);

  c->status.remove = 1;
  
  if(c->socket)
    close(c->socket);

  if(c->edge)
    {
      if(report)
        {
          for(node = connection_tree->head; node; node = node->next)
            {
              other = (connection_t *)node->data;
              if(other->status.active && other != c)
                send_del_edge(other, c->edge);
            }
        }

      edge_del(c->edge);
    }

  /* Run MST and SSSP algorithms */
  
  graph();

  /* Check if this was our outgoing connection */

  if(c->outgoing)
    {
      retry_outgoing(c->outgoing);
      c->outgoing = NULL;
    }

  /* Deactivate */

  c->status.active = 0;
  if(c->node)
    c->node->connection = NULL;
  do_prune = 1;
cp
}

/*
  Check if the other end is active.
  If we have sent packets, but didn't receive any,
  then possibly the other end is dead. We send a
  PING request over the meta connection. If the other
  end does not reply in time, we consider them dead
  and close the connection.
*/
void check_dead_connections(void)
{
  time_t now;
  avl_node_t *node, *next;
  connection_t *c;
cp
  now = time(NULL);

  for(node = connection_tree->head; node; node = next)
    {
      next = node->next;
      c = (connection_t *)node->data;
      if(c->last_ping_time + pingtimeout < now)
        {
          if(c->status.active)
            {
              if(c->status.pinged)
                {
                  if(debug_lvl >= DEBUG_PROTOCOL)
  	            syslog(LOG_INFO, _("%s (%s) didn't respond to PING"),
		           c->name, c->hostname);
	          c->status.timeout = 1;
	          terminate_connection(c, 1);
                }
              else
                {
                  send_ping(c);
                }
            }
          else
            {
              if(debug_lvl >= DEBUG_CONNECTIONS)
                syslog(LOG_WARNING, _("Timeout from %s (%s) during authentication"),
                       c->name, c->hostname);
              terminate_connection(c, 0);
            }
        }
    }
cp
}

/*
  accept a new tcp connect and create a
  new connection
*/
int handle_new_meta_connection()
{
  connection_t *new;
  struct sockaddr client;
  int fd, len = sizeof(client);
cp
  if((fd = accept(tcp_socket, &client, &len)) < 0)
    {
      syslog(LOG_ERR, _("Accepting a new connection failed: %m"));
      return -1;
    }

  if(!(new = create_new_connection(fd)))
    {
      shutdown(fd, 2);
      close(fd);
      syslog(LOG_NOTICE, _("Closed attempted connection"));
      return 0;
    }

  connection_add(new);

  send_id(new);
cp
  return 0;
}

void try_outgoing_connections(void)
{
  static config_t *cfg = NULL;
  char *name;
  outgoing_t *outgoing;
cp
  for(cfg = lookup_config(config_tree, "ConnectTo"); cfg; cfg = lookup_config_next(config_tree, cfg))
    {
      get_config_string(cfg, &name);

      if(check_id(name))
        {
          syslog(LOG_ERR, _("Invalid name for outgoing connection in %s line %d"), cfg->file, cfg->line);
          free(name);
          continue;
        }

      outgoing = xmalloc_and_zero(sizeof(*outgoing));
      outgoing->name = name;
      setup_outgoing_connection(outgoing);
    }
}

/*
  check all connections to see if anything
  happened on their sockets
*/
void check_network_activity(fd_set *f)
{
  connection_t *c;
  avl_node_t *node;
cp
  if(FD_ISSET(udp_socket, f))
    handle_incoming_vpn_data();

  for(node = connection_tree->head; node; node = node->next)
    {
      c = (connection_t *)node->data;

      if(c->status.remove)
	return;

      if(FD_ISSET(c->socket, f))
	if(receive_meta(c) < 0)
	  {
	    terminate_connection(c, c->status.active);
	    return;
	  }
    }

  if(FD_ISSET(tcp_socket, f))
    handle_new_meta_connection();
cp
}

void prune_connections(void)
{
  connection_t *c;
  avl_node_t *node, *next;
cp
  for(node = connection_tree->head; node; node = next)
    {
      next = node->next;
      c = (connection_t *)node->data;

      if(c->status.remove)
	connection_del(c);
    }
  
  if(!connection_tree->head)
    purge();
cp
}

/*
  this is where it all happens...
*/
void main_loop(void)
{
  fd_set fset;
  struct timeval tv;
  int r;
  time_t last_ping_check;
  int t;
  event_t *event;
  vpn_packet_t packet;
cp
  last_ping_check = time(NULL);

  srand(time(NULL));

  for(;;)
    {
      tv.tv_sec = 1 + (rand() & 7); /* Approx. 5 seconds, randomized to prevent global synchronisation effects */
      tv.tv_usec = 0;

      if(do_prune)
        {
          prune_connections();
          do_prune = 0;
        }

      build_fdset(&fset);

      if((r = select(FD_SETSIZE, &fset, NULL, NULL, &tv)) < 0)
        {
	  if(errno != EINTR) /* because of a signal */
            {
              syslog(LOG_ERR, _("Error while waiting for input: %m"));
              return;
            }
        }

      if(sighup)
        {
          syslog(LOG_INFO, _("Rereading configuration file and restarting in 5 seconds"));
          sighup = 0;
          close_network_connections();
          exit_configuration(&config_tree);

          if(read_server_config())
            {
              syslog(LOG_ERR, _("Unable to reread configuration file, exiting"));
              exit(1);
            }

          sleep(5);

          if(setup_network_connections())
            return;

          continue;
        }

      if(do_purge)
        {
	  purge();
	  do_purge = 0;
	}

      t = time(NULL);

      /* Let's check if everybody is still alive */

      if(last_ping_check + pingtimeout < t)
	{
	  check_dead_connections();
          last_ping_check = time(NULL);

          /* Should we regenerate our key? */

          if(keyexpires < t)
            {
              if(debug_lvl >= DEBUG_STATUS)
                syslog(LOG_INFO, _("Regenerating symmetric key"));

              RAND_pseudo_bytes(myself->key, myself->keylength);
              send_key_changed(myself->connection, myself);
              keyexpires = time(NULL) + keylifetime;
            }
	}

      if(sigalrm)
        {
          syslog(LOG_INFO, _("Flushing event queue"));

	  while(event_tree->head)
	    {
	      event = (event_t *)event_tree->head->data;
	      event->handler(event->data);
	      event_del(event);
	    }
	  sigalrm = 0;
        }

      while((event = get_expired_event()))
        {
	  event->handler(event->data);
          free(event);
	}

      if(r > 0)
        {
          check_network_activity(&fset);

          /* local tap data */
          if(FD_ISSET(device_fd, &fset))
            {
              if(!read_packet(&packet))
                route_outgoing(&packet);
            }
        }
    }
cp
}
