/*
    net.c -- most of the network code
    Copyright (C) 1998-2001 Ivo Timmermans <itimmermans@bigfoot.com>,
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

    $Id: net.c,v 1.35.4.123 2001/07/20 20:25:10 guus Exp $
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
#include <sys/signal.h>
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

#ifndef HAVE_RAND_PSEUDO_BYTES
#define RAND_pseudo_bytes RAND_bytes
#endif

#ifdef HAVE_TUNTAP
 #ifdef HAVE_LINUX
  #ifdef LINUX_IF_TUN_H
   #include LINUX_IF_TUN_H
  #else
   #include <linux/if_tun.h>
  #endif
 #else
  #include <net/if_tun.h>
 #endif
#endif

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
#include "process.h"
#include "route.h"

#include "system.h"

int tap_fd = -1;
int taptype = TAP_TYPE_ETHERTAP;
int total_tap_in = 0;
int total_tap_out = 0;
int total_socket_in = 0;
int total_socket_out = 0;

config_t *upstreamcfg;
int seconds_till_retry = 5;

int keylifetime = 0;
int keyexpires = 0;

void send_udppacket(connection_t *cl, vpn_packet_t *inpkt)
{
  vpn_packet_t outpkt;
  int outlen, outpad;
  EVP_CIPHER_CTX ctx;
  struct sockaddr_in to;
  socklen_t tolen = sizeof(to);
  vpn_packet_t *copy;
cp
  if(!cl->status.validkey)
    {
      if(debug_lvl >= DEBUG_TRAFFIC)
	syslog(LOG_INFO, _("No valid key known yet for %s (%s), queueing packet"),
	       cl->name, cl->hostname);

      /* Since packet is on the stack of handle_tap_input(),
         we have to make a copy of it first. */

      copy = xmalloc(sizeof(vpn_packet_t));
      memcpy(copy, inpkt, sizeof(vpn_packet_t));

      list_insert_tail(cl->queue, copy);

      if(!cl->status.waitingforkey)
	send_req_key(myself, cl);
      return;
    }

  /* Encrypt the packet. */

  RAND_pseudo_bytes(inpkt->salt, sizeof(inpkt->salt));

  EVP_EncryptInit(&ctx, cl->cipher_pkttype, cl->cipher_pktkey, cl->cipher_pktkey + cl->cipher_pkttype->key_len);
  EVP_EncryptUpdate(&ctx, outpkt.salt, &outlen, inpkt->salt, inpkt->len + sizeof(inpkt->salt));
  EVP_EncryptFinal(&ctx, outpkt.salt + outlen, &outpad);
  outlen += outpad;

  total_socket_out += outlen;

  to.sin_family = AF_INET;
  to.sin_addr.s_addr = htonl(cl->address);
  to.sin_port = htons(cl->port);

  if((sendto(myself->socket, (char *) outpkt.salt, outlen, 0, (const struct sockaddr *)&to, tolen)) < 0)
    {
      syslog(LOG_ERR, _("Error sending packet to %s (%s): %m"),
             cl->name, cl->hostname);
      return;
    }
cp
}

void receive_packet(connection_t *cl, vpn_packet_t *packet)
{
cp
  if(debug_lvl >= DEBUG_TRAFFIC)
    syslog(LOG_DEBUG, _("Received packet of %d bytes from %s (%s)"), packet->len, cl->name, cl->hostname);

  route_incoming(cl, packet);
cp
}

void receive_udppacket(connection_t *cl, vpn_packet_t *inpkt)
{
  vpn_packet_t outpkt;
  int outlen, outpad;
  EVP_CIPHER_CTX ctx;
cp
  /* Decrypt the packet */

  EVP_DecryptInit(&ctx, myself->cipher_pkttype, myself->cipher_pktkey, myself->cipher_pktkey + myself->cipher_pkttype->key_len);
  EVP_DecryptUpdate(&ctx, outpkt.salt, &outlen, inpkt->salt, inpkt->len);
  EVP_DecryptFinal(&ctx, outpkt.salt + outlen, &outpad);
  outlen += outpad;
  outpkt.len = outlen - sizeof(outpkt.salt);

  total_socket_in += outlen;

  receive_packet(cl, &outpkt);
cp
}

void receive_tcppacket(connection_t *cl, char *buffer, int len)
{
  vpn_packet_t outpkt;
cp
  outpkt.len = len;
  memcpy(outpkt.data, buffer, len);

  receive_packet(cl, &outpkt);
cp
}

void accept_packet(vpn_packet_t *packet)
{
cp
  if(debug_lvl >= DEBUG_TRAFFIC)
    syslog(LOG_DEBUG, _("Writing packet of %d bytes to tap device"),
           packet->len);

  if(taptype == TAP_TYPE_TUNTAP)
    {
      if(write(tap_fd, packet->data, packet->len) < 0)
        syslog(LOG_ERR, _("Can't write to tun/tap device: %m"));
      else
        total_tap_out += packet->len;
    }
  else	/* ethertap */
    {
      if(write(tap_fd, packet->data - 2, packet->len + 2) < 0)
        syslog(LOG_ERR, _("Can't write to ethertap device: %m"));
      else
        total_tap_out += packet->len;
    }
cp
}

/*
  send a packet to the given vpn ip.
*/
void send_packet(connection_t *cl, vpn_packet_t *packet)
{
cp
  if(debug_lvl >= DEBUG_TRAFFIC)
    syslog(LOG_ERR, _("Sending packet of %d bytes to %s (%s)"),
           packet->len, cl->name, cl->hostname);

  if(cl == myself)
    {
      if(debug_lvl >= DEBUG_TRAFFIC)
        {
          syslog(LOG_NOTICE, _("Packet is looping back to us!"));
        }

      return;
    }

  if(!cl->status.active)
    {
      if(debug_lvl >= DEBUG_TRAFFIC)
	syslog(LOG_INFO, _("%s (%s) is not active, dropping packet"),
	       cl->name, cl->hostname);

      return;
    }

  /* Check if it has to go via TCP or UDP... */
cp
  if((cl->options | myself->options) & OPTION_TCPONLY)
    {
      if(send_tcppacket(cl, packet))
        terminate_connection(cl);
    }
  else
    send_udppacket(cl, packet);
}

/* Broadcast a packet to all active direct connections */

void broadcast_packet(connection_t *from, vpn_packet_t *packet)
{
  avl_node_t *node;
  connection_t *cl;
cp
  if(debug_lvl >= DEBUG_TRAFFIC)
    syslog(LOG_INFO, _("Broadcasting packet of %d bytes from %s (%s)"),
	   packet->len, from->name, from->hostname);

  for(node = connection_tree->head; node; node = node->next)
    {
      cl = (connection_t *)node->data;
      if(cl->status.active && cl != from)
        send_packet(cl, packet);
    }
cp
}

void flush_queue(connection_t *cl)
{
  list_node_t *node, *next;
cp
  if(debug_lvl >= DEBUG_TRAFFIC)
    syslog(LOG_INFO, _("Flushing queue for %s (%s)"), cl->name, cl->hostname);

  for(node = cl->queue->head; node; node = next)
    {
      next = node->next;
      send_udppacket(cl, (vpn_packet_t *)node->data);
      list_delete_node(cl->queue, node);
    }
cp
}

/*
  open the local ethertap device
*/
int setup_tap_fd(void)
{
  int nfd;
  const char *tapfname;
  config_t const *cfg;
#ifdef HAVE_LINUX
# ifdef HAVE_TUNTAP
  struct ifreq ifr;
# endif
#endif

cp
  if((cfg = get_config_val(config, config_tapdevice)))
    tapfname = cfg->data.ptr;
  else
   {
#ifdef HAVE_LINUX
# ifdef HAVE_TUNTAP
      tapfname = "/dev/net/tun";
# else
      tapfname = "/dev/tap0";
# endif
#endif
#ifdef HAVE_FREEBSD
      tapfname = "/dev/tap0";
#endif
#ifdef HAVE_SOLARIS
      tapfname = "/dev/tun";
#endif
   }
cp
  if((nfd = open(tapfname, O_RDWR | O_NONBLOCK)) < 0)
    {
      syslog(LOG_ERR, _("Could not open %s: %m"), tapfname);
      return -1;
    }
cp
  tap_fd = nfd;

  taptype = TAP_TYPE_ETHERTAP;

  /* Set default MAC address for ethertap devices */

  mymac.type = SUBNET_MAC;
  mymac.net.mac.address.x[0] = 0xfe;
  mymac.net.mac.address.x[1] = 0xfd;
  mymac.net.mac.address.x[2] = 0x00;
  mymac.net.mac.address.x[3] = 0x00;
  mymac.net.mac.address.x[4] = 0x00;
  mymac.net.mac.address.x[5] = 0x00;

#ifdef HAVE_LINUX
 #ifdef HAVE_TUNTAP
  /* Ok now check if this is an old ethertap or a new tun/tap thingie */
  memset(&ifr, 0, sizeof(ifr));
cp
  ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
  if (netname)
    strncpy(ifr.ifr_name, netname, IFNAMSIZ);
cp
  if (!ioctl(tap_fd, TUNSETIFF, (void *) &ifr))
  {
    syslog(LOG_INFO, _("%s is a new style tun/tap device"), tapfname);
    taptype = TAP_TYPE_TUNTAP;
  }
 #endif
#else
 taptype = TAP_TYPE_TUNTAP;
#endif
cp
  return 0;
}

/*
  set up the socket that we listen on for incoming
  (tcp) connections
*/
int setup_listen_meta_socket(int port)
{
  int nfd, flags;
  struct sockaddr_in a;
  int option;
  config_t const *cfg;
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

  if((cfg = get_config_val(config, config_interface)))
    {
      if(setsockopt(nfd, SOL_SOCKET, SO_BINDTODEVICE, cfg->data.ptr, strlen(cfg->data.ptr)))
        {
          close(nfd);
          syslog(LOG_ERR, _("Unable to bind listen socket to interface %s: %m"), cfg->data.ptr);
          return -1;
        }
    }
#endif

  memset(&a, 0, sizeof(a));
  a.sin_family = AF_INET;
  a.sin_port = htons(port);

  if((cfg = get_config_val(config, config_interfaceip)))
    a.sin_addr.s_addr = htonl(cfg->data.ip->address);
  else
    a.sin_addr.s_addr = htonl(INADDR_ANY);

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

/*
  setup the socket for incoming encrypted
  data (the udp part)
*/
int setup_vpn_in_socket(int port)
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

/*
  setup an outgoing meta (tcp) socket
*/
int setup_outgoing_meta_socket(connection_t *cl)
{
  int flags;
  struct sockaddr_in a;
  config_t const *cfg;
  int option;
cp
  if(debug_lvl >= DEBUG_CONNECTIONS)
    syslog(LOG_INFO, _("Trying to connect to %s"), cl->hostname);

  if((cfg = get_config_val(cl->config, config_port)) == NULL)
    cl->port = 655;
  else
    cl->port = cfg->data.val;

  cl->meta_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if(cl->meta_socket == -1)
    {
      syslog(LOG_ERR, _("Creating socket for %s port %d failed: %m"),
             cl->hostname, cl->port);
      return -1;
    }

  /* Bind first to get a fix on our source port */

  a.sin_family = AF_INET;
  a.sin_port = htons(0);
  a.sin_addr.s_addr = htonl(INADDR_ANY);

  if(bind(cl->meta_socket, (struct sockaddr *)&a, sizeof(struct sockaddr)))
    {
      close(cl->meta_socket);
      syslog(LOG_ERR, _("System call `%s' failed: %m"), "bind");
      return -1;
    }

  /* Optimize TCP settings */

  option = 1;
  setsockopt(cl->meta_socket, SOL_SOCKET, SO_KEEPALIVE, &option, sizeof(option));
#ifdef HAVE_LINUX
  setsockopt(cl->meta_socket, SOL_TCP, TCP_NODELAY, &option, sizeof(option));

  option = IPTOS_LOWDELAY;
  setsockopt(cl->meta_socket, SOL_IP, IP_TOS, &option, sizeof(option));
#endif
  /* Connect */

  a.sin_family = AF_INET;
  a.sin_port = htons(cl->port);
  a.sin_addr.s_addr = htonl(cl->address);

  if(connect(cl->meta_socket, (struct sockaddr *)&a, sizeof(a)) == -1)
    {
      close(cl->meta_socket);
      syslog(LOG_ERR, _("%s port %hd: %m"), cl->hostname, cl->port);
      return -1;
    }

  flags = fcntl(cl->meta_socket, F_GETFL);
  if(fcntl(cl->meta_socket, F_SETFL, flags | O_NONBLOCK) < 0)
    {
      close(cl->meta_socket);
      syslog(LOG_ERR, _("fcntl for %s port %d: %m"),
             cl->hostname, cl->port);
      return -1;
    }

  if(debug_lvl >= DEBUG_CONNECTIONS)
    syslog(LOG_INFO, _("Connected to %s port %hd"),
         cl->hostname, cl->port);

  cl->status.meta = 1;
cp
  return 0;
}

/*
  Setup an outgoing meta connection.
*/
int setup_outgoing_connection(char *name)
{
  connection_t *ncn, *old;
  struct hostent *h;
  config_t const *cfg;
cp
  if(check_id(name))
    {
      syslog(LOG_ERR, _("Invalid name for outgoing connection"));
      return -1;
    }

  /* Make sure we don't make an outgoing connection to a host that is already in our connection list */

  if((old = lookup_id(name)))
    {
      if(debug_lvl >= DEBUG_CONNECTIONS)
        syslog(LOG_NOTICE, _("We are already connected to %s."), name);
      old->status.outgoing = 1;
      return 0;
    }
    
  ncn = new_connection();
  asprintf(&ncn->name, "%s", name);

  if(read_host_config(ncn))
    {
      syslog(LOG_ERR, _("Error reading host configuration file for %s"), ncn->name);
      free_connection(ncn);
      return -1;
    }

  if(!(cfg = get_config_val(ncn->config, config_address)))
    {
      syslog(LOG_ERR, _("No address specified for %s"), ncn->name);
      free_connection(ncn);
      return -1;
    }

  if(!(h = gethostbyname(cfg->data.ptr)))
    {
      syslog(LOG_ERR, _("Error looking up `%s': %m"), cfg->data.ptr);
      free_connection(ncn);
      return -1;
    }

  ncn->address = ntohl(*((ipv4_t*)(h->h_addr_list[0])));
  ncn->hostname = hostlookup(htonl(ncn->address));

  if(setup_outgoing_meta_socket(ncn) < 0)
    {
      syslog(LOG_ERR, _("Could not set up a meta connection to %s"),
             ncn->hostname);
      free_connection(ncn);
      return -1;
    }

  ncn->status.outgoing = 1;
  ncn->buffer = xmalloc(MAXBUFSIZE);
  ncn->buflen = 0;
  ncn->last_ping_time = time(NULL);

  connection_add(ncn);

  send_id(ncn);
cp
  return 0;
}

int read_rsa_public_key(connection_t *cl)
{
  config_t const *cfg;
  FILE *fp;
  char *fname;
  void *result;
cp
  if(!cl->rsa_key)
    cl->rsa_key = RSA_new();

  /* First, check for simple PublicKey statement */

  if((cfg = get_config_val(cl->config, config_publickey)))
    {
      BN_hex2bn(&cl->rsa_key->n, cfg->data.ptr);
      BN_hex2bn(&cl->rsa_key->e, "FFFF");
      return 0;
    }

  /* Else, check for PublicKeyFile statement and read it */

  if((cfg = get_config_val(cl->config, config_publickeyfile)))
    {
      if(is_safe_path(cfg->data.ptr))
        {
          if((fp = fopen(cfg->data.ptr, "r")) == NULL)
            {
              syslog(LOG_ERR, _("Error reading RSA public key file `%s': %m"),
	             cfg->data.ptr);
              return -1;
            }
          result = PEM_read_RSAPublicKey(fp, &cl->rsa_key, NULL, NULL);
          fclose(fp);
          if(!result)
            {
              syslog(LOG_ERR, _("Reading RSA public key file `%s' failed: %m"),
	             cfg->data.ptr);
              return -1;
            }
          return 0;
        }
      else
        return -1;
    }

  /* Else, check if a harnessed public key is in the config file */

  asprintf(&fname, "%s/hosts/%s", confbase, cl->name);
  if((fp = fopen(fname, "r")))
    {
      result = PEM_read_RSAPublicKey(fp, &cl->rsa_key, NULL, NULL);
      fclose(fp);
      free(fname);
      if(result)
        return 0;
    }

  free(fname);

  /* Nothing worked. */

  syslog(LOG_ERR, _("No public key for %s specified!"), cl->name);
cp
  return -1;
}

int read_rsa_private_key(void)
{
  config_t const *cfg;
  FILE *fp;
  void *result;
cp
  if(!myself->rsa_key)
    myself->rsa_key = RSA_new();

  if((cfg = get_config_val(config, config_privatekey)))
    {
      BN_hex2bn(&myself->rsa_key->d, cfg->data.ptr);
      BN_hex2bn(&myself->rsa_key->e, "FFFF");
    }
  else if((cfg = get_config_val(config, config_privatekeyfile)))
    {
      if((fp = fopen(cfg->data.ptr, "r")) == NULL)
        {
          syslog(LOG_ERR, _("Error reading RSA private key file `%s': %m"),
	         cfg->data.ptr);
          return -1;
        }
      result = PEM_read_RSAPrivateKey(fp, &myself->rsa_key, NULL, NULL);
      fclose(fp);
      if(!result)
        {
          syslog(LOG_ERR, _("Reading RSA private key file `%s' failed: %m"),
	         cfg->data.ptr);
          return -1;
        }
    }
  else
    {
      syslog(LOG_ERR, _("No private key for tinc daemon specified!"));
      return -1;
    }
cp
  return 0;
}

/*
  Configure connection_t myself and set up the local sockets (listen only)
*/
int setup_myself(void)
{
  config_t const *cfg;
  config_t *next;
  subnet_t *net;
cp
  myself = new_connection();

  asprintf(&myself->hostname, _("MYSELF"));
  myself->options = 0;
  myself->protocol_version = PROT_CURRENT;

  if(!(cfg = get_config_val(config, config_name))) /* Not acceptable */
    {
      syslog(LOG_ERR, _("Name for tinc daemon required!"));
      return -1;
    }
  else
    asprintf(&myself->name, "%s", (char*)cfg->data.val);

  if(check_id(myself->name))
    {
      syslog(LOG_ERR, _("Invalid name for myself!"));
      return -1;
    }
cp
  if(read_rsa_private_key())
    return -1;

  if(read_host_config(myself))
    {
      syslog(LOG_ERR, _("Cannot open host configuration file for myself!"));
      return -1;
    }

  if(read_rsa_public_key(myself))
    return -1;
cp

/*
  if(RSA_check_key(myself->rsa_key) != 1)
    {
      syslog(LOG_ERR, _("Invalid public/private keypair!"));
      return -1;
    }
*/
  if(!(cfg = get_config_val(myself->config, config_port)))
    myself->port = 655;
  else
    myself->port = cfg->data.val;

/* Read in all the subnets specified in the host configuration file */

  for(next = myself->config; (cfg = get_config_val(next, config_subnet)); next = cfg->next)
    {
      net = new_subnet();
      net->type = SUBNET_IPV4;
      net->net.ipv4.address = cfg->data.ip->address;
      net->net.ipv4.mask = cfg->data.ip->mask;

      /* Teach newbies what subnets are... */

      if((net->net.ipv4.address & net->net.ipv4.mask) != net->net.ipv4.address)
        {
          syslog(LOG_ERR, _("Network address and subnet mask do not match!"));
          return -1;
        }

      subnet_add(myself, net);
    }

cp
  /* Check some options */

  if((cfg = get_config_val(config, config_indirectdata)))
    if(cfg->data.val == stupid_true)
      myself->options |= OPTION_INDIRECT;

  if((cfg = get_config_val(config, config_tcponly)))
    if(cfg->data.val == stupid_true)
      myself->options |= OPTION_TCPONLY;

  if((cfg = get_config_val(myself->config, config_indirectdata)))
    if(cfg->data.val == stupid_true)
      myself->options |= OPTION_INDIRECT;

  if((cfg = get_config_val(myself->config, config_tcponly)))
    if(cfg->data.val == stupid_true)
      myself->options |= OPTION_TCPONLY;

  if(myself->options & OPTION_TCPONLY)
    myself->options |= OPTION_INDIRECT;

  if((cfg = get_config_val(config, config_mode)))
    {
      if(!strcasecmp(cfg->data.ptr, "router"))
        routing_mode = RMODE_ROUTER;
      else if (!strcasecmp(cfg->data.ptr, "switch"))
        routing_mode = RMODE_SWITCH;
      else if (!strcasecmp(cfg->data.ptr, "hub"))
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
  
  if((myself->meta_socket = setup_listen_meta_socket(myself->port)) < 0)
    {
      syslog(LOG_ERR, _("Unable to set up a listening TCP socket!"));
      return -1;
    }

  if((myself->socket = setup_vpn_in_socket(myself->port)) < 0)
    {
      syslog(LOG_ERR, _("Unable to set up a listening UDP socket!"));
      return -1;
    }
cp
  /* Generate packet encryption key */

  myself->cipher_pkttype = EVP_bf_cbc();

  myself->cipher_pktkeylength = myself->cipher_pkttype->key_len + myself->cipher_pkttype->iv_len;

  myself->cipher_pktkey = (char *)xmalloc(myself->cipher_pktkeylength);
  RAND_pseudo_bytes(myself->cipher_pktkey, myself->cipher_pktkeylength);

  if(!(cfg = get_config_val(config, config_keyexpire)))
    keylifetime = 3600;
  else
    keylifetime = cfg->data.val;

  keyexpires = time(NULL) + keylifetime;
cp
  /* Done */

  myself->status.active = 1;
  id_add(myself);

  syslog(LOG_NOTICE, _("Ready: listening on port %hd"), myself->port);
cp
  return 0;
}

RETSIGTYPE
sigalrm_handler(int a)
{
  config_t const *cfg;
cp
  cfg = get_config_val(upstreamcfg, config_connectto);

  if(!cfg)
    {
      if(upstreamcfg == config)
      {
        /* No upstream IP given, we're listen only. */
        signal(SIGALRM, SIG_IGN);
        return;
      }
    }
  else
    {
      /* We previously tried all the ConnectTo lines. Now wrap back to the first. */
      cfg = get_config_val(config, config_connectto);
    }
    
  while(cfg)
    {
      upstreamcfg = cfg->next;
      if(!setup_outgoing_connection(cfg->data.ptr))   /* function returns 0 when there are no problems */
        {
          signal(SIGALRM, SIG_IGN);
          return;
        }
      cfg = get_config_val(upstreamcfg, config_connectto); /* Or else we try the next ConnectTo line */
    }

  signal(SIGALRM, sigalrm_handler);
  upstreamcfg = config;
  seconds_till_retry += 5;
  if(seconds_till_retry > MAXTIMEOUT)    /* Don't wait more than MAXTIMEOUT seconds. */
    seconds_till_retry = MAXTIMEOUT;
  syslog(LOG_ERR, _("Still failed to connect to other, will retry in %d seconds"),
	 seconds_till_retry);
  alarm(seconds_till_retry);
cp
}

/*
  setup all initial network connections
*/
int setup_network_connections(void)
{
  config_t const *cfg;
cp
  init_connections();
  init_subnets();

  if((cfg = get_config_val(config, config_pingtimeout)) == NULL)
    timeout = 60;
  else
    {
      timeout = cfg->data.val;
      if(timeout < 1)
        {
          timeout = 86400;
        }
     }

  if(setup_tap_fd() < 0)
    return -1;

  /* Run tinc-up script to further initialize the tap interface */
  execute_script("tinc-up");

  if(setup_myself() < 0)
    return -1;

  if(!(cfg = get_config_val(config, config_connectto)))
    /* No upstream IP given, we're listen only. */
    return 0;

  while(cfg)
    {
      upstreamcfg = cfg->next;
      if(!setup_outgoing_connection(cfg->data.ptr))   /* function returns 0 when there are no problems */
        return 0;
      cfg = get_config_val(upstreamcfg, config_connectto); /* Or else we try the next ConnectTo line */
    }

  if(do_detach)
    {
      signal(SIGALRM, sigalrm_handler);
      upstreamcfg = config;
      seconds_till_retry = MAXTIMEOUT;
      syslog(LOG_NOTICE, _("Trying to re-establish outgoing connection in %d seconds"), seconds_till_retry);
      alarm(seconds_till_retry);
    }
  else
    return -1;

cp
  return 0;
}

/*
  close all open network connections
*/
void close_network_connections(void)
{
  avl_node_t *node, *next;
  connection_t *p;
cp
  for(node = connection_tree->head; node; node = next)
    {
      next = node->next;
      p = (connection_t *)node->data;
      p->status.outgoing = 0;
      terminate_connection(p);
    }

  terminate_connection(myself);

  destroy_trees();

  execute_script("tinc-down");

  close(tap_fd);
cp
  return;
}

/*
  handle an incoming tcp connect call and open
  a connection to it.
*/
connection_t *create_new_connection(int sfd)
{
  connection_t *p;
  struct sockaddr_in ci;
  int len = sizeof(ci);
cp
  p = new_connection();

  if(getpeername(sfd, (struct sockaddr *) &ci, (socklen_t *) &len) < 0)
    {
      syslog(LOG_ERR, _("System call `%s' failed: %m"),
	     "getpeername");
      close(sfd);
      return NULL;
    }

  asprintf(&p->name, _("UNKNOWN"));
  p->address = ntohl(ci.sin_addr.s_addr);
  p->hostname = hostlookup(ci.sin_addr.s_addr);
  p->port = htons(ci.sin_port);				/* This one will be overwritten later */
  p->meta_socket = sfd;
  p->status.meta = 1;
  p->buffer = xmalloc(MAXBUFSIZE);
  p->buflen = 0;
  p->last_ping_time = time(NULL);

  if(debug_lvl >= DEBUG_CONNECTIONS)
    syslog(LOG_NOTICE, _("Connection from %s port %d"),
         p->hostname, htons(ci.sin_port));

  p->allow_request = ID;
cp
  return p;
}

/*
  put all file descriptors in an fd_set array
*/
void build_fdset(fd_set *fs)
{
  avl_node_t *node;
  connection_t *p;
cp
  FD_ZERO(fs);

  FD_SET(myself->socket, fs);

  for(node = connection_tree->head; node; node = node->next)
    {
      p = (connection_t *)node->data;
      FD_SET(p->meta_socket, fs);
    }

  FD_SET(myself->meta_socket, fs);
  FD_SET(tap_fd, fs);
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
  connection_t *cl;
cp
  if(getsockopt(myself->socket, SOL_SOCKET, SO_ERROR, &x, &l) < 0)
    {
      syslog(LOG_ERR, _("This is a bug: %s:%d: %d:%m"),
	     __FILE__, __LINE__, myself->socket);
      return;
    }
  if(x)
    {
      syslog(LOG_ERR, _("Incoming data socket error: %s"), strerror(x));
      return;
    }

  if((pkt.len = recvfrom(myself->socket, (char *) pkt.salt, MTU, 0, (struct sockaddr *)&from, &fromlen)) <= 0)
    {
      syslog(LOG_ERR, _("Receiving packet failed: %m"));
      return;
    }

  cl = lookup_active(ntohl(from.sin_addr.s_addr), ntohs(from.sin_port));

  if(!cl)
    {
      syslog(LOG_WARNING, _("Received UDP packets on port %hd from unknown source %x:%hd"), myself->port, ntohl(from.sin_addr.s_addr), ntohs(from.sin_port));
      return;
    }

  cl->last_ping_time = time(NULL);

  receive_udppacket(cl, &pkt);
cp
}

/*
  Terminate a connection:
  - Close the sockets
  - Remove associated hosts and subnets
  - Deactivate the host
  - Since it might still be referenced, put it on the prune list.
*/
void terminate_connection(connection_t *cl)
{
  connection_t *p;
  subnet_t *subnet;
  avl_node_t *node, *next;
cp
  if(cl->status.remove)
    return;
  else
    cl->status.remove = 1;

  if(cl->socket)
    close(cl->socket);

  if(cl->status.meta)
    {
      if(debug_lvl >= DEBUG_CONNECTIONS)
        syslog(LOG_NOTICE, _("Closing connection with %s (%s)"),
               cl->name, cl->hostname);

      close(cl->meta_socket);

      /* Find all connections that were lost because they were behind cl
         (the connection that was dropped). */

        for(node = active_tree->head; node; node = next)
          {
            next = node->next;
            p = (connection_t *)node->data;
            if(p->nexthop == cl && p != cl)
              terminate_connection(p);
          }

      /* Inform others of termination if it was still active */

      if(cl->status.active)
        for(node = connection_tree->head; node; node = node->next)
          {
            p = (connection_t *)node->data;
            if(p->status.active && p != cl)
              send_del_host(p, cl);	/* Sounds like recursion, but p does not have a meta connection :) */
          }
    }

  /* Remove the associated subnets */

  for(node = cl->subnet_tree->head; node; node = next)
    {
      next = node->next;
      subnet = (subnet_t *)node->data;
      subnet_del(subnet);
    }

  /* Check if this was our outgoing connection */

  if(cl->status.outgoing)
    {
      cl->status.outgoing = 0;
      signal(SIGALRM, sigalrm_handler);
      alarm(seconds_till_retry);
      syslog(LOG_NOTICE, _("Trying to re-establish outgoing connection in %d seconds"), seconds_till_retry);
    }
cp
  /* Schedule it for pruning */

  prune_add(cl);
  connection_del(cl);
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
  avl_node_t *node;
  connection_t *cl;
cp
  now = time(NULL);

  for(node = connection_tree->head; node; node = node->next)
    {
      cl = (connection_t *)node->data;
      if(cl->status.active)
        {
          if(cl->last_ping_time + timeout < now)
            {
              if(cl->status.pinged)
                {
                  if(debug_lvl >= DEBUG_PROTOCOL)
  	            syslog(LOG_INFO, _("%s (%s) didn't respond to PING"),
		           cl->name, cl->hostname);
	          cl->status.timeout = 1;
	          terminate_connection(cl);
                }
              else
                {
                  send_ping(cl);
                }
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
  connection_t *ncn;
  struct sockaddr client;
  int nfd, len = sizeof(client);
cp
  if((nfd = accept(myself->meta_socket, &client, &len)) < 0)
    {
      syslog(LOG_ERR, _("Accepting a new connection failed: %m"));
      return -1;
    }

  if(!(ncn = create_new_connection(nfd)))
    {
      shutdown(nfd, 2);
      close(nfd);
      syslog(LOG_NOTICE, _("Closed attempted connection"));
      return 0;
    }

  connection_add(ncn);

  send_id(ncn);
cp
  return 0;
}

/*
  check all connections to see if anything
  happened on their sockets
*/
void check_network_activity(fd_set *f)
{
  connection_t *p;
  avl_node_t *node;
cp
  if(FD_ISSET(myself->socket, f))
    handle_incoming_vpn_data();

  for(node = connection_tree->head; node; node = node->next)
    {
      p = (connection_t *)node->data;

      if(p->status.remove)
	return;

      if(FD_ISSET(p->meta_socket, f))
	if(receive_meta(p) < 0)
	  {
	    terminate_connection(p);
	    return;
	  }
    }

  if(FD_ISSET(myself->meta_socket, f))
    handle_new_meta_connection();
cp
}

/*
  read, encrypt and send data that is
  available through the ethertap device
*/
void handle_tap_input(void)
{
  vpn_packet_t vp;
  int lenin;
cp
  if(taptype == TAP_TYPE_TUNTAP)
    {
      if((lenin = read(tap_fd, vp.data, MTU)) <= 0)
        {
          syslog(LOG_ERR, _("Error while reading from tun/tap device: %m"));
          return;
        }
      vp.len = lenin;
    }
  else			/* ethertap */
    {
      if((lenin = read(tap_fd, vp.data - 2, MTU)) <= 0)
        {
          syslog(LOG_ERR, _("Error while reading from ethertap device: %m"));
          return;
        }
      vp.len = lenin - 2;
    }

  total_tap_in += vp.len;

  if(lenin < 32)
    {
      if(debug_lvl >= DEBUG_TRAFFIC)
	syslog(LOG_WARNING, _("Received short packet from tap device"));
      return;
    }

  if(debug_lvl >= DEBUG_TRAFFIC)
    {
      syslog(LOG_DEBUG, _("Read packet of length %d from tap device"), vp.len);
    }

  route_outgoing(&vp);
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
cp
  last_ping_check = time(NULL);

  for(;;)
    {
      tv.tv_sec = timeout;
      tv.tv_usec = 0;

      prune_flush();
      build_fdset(&fset);

      if((r = select(FD_SETSIZE, &fset, NULL, NULL, &tv)) < 0)
        {
	  if(errno != EINTR) /* because of alarm */
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
          clear_config(&config);

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

      t = time(NULL);

      /* Let's check if everybody is still alive */

      if(last_ping_check + timeout < t)
	{
	  check_dead_connections();
          last_ping_check = time(NULL);

          /* Should we regenerate our key? */

          if(keyexpires < t)
            {
              if(debug_lvl >= DEBUG_STATUS)
                syslog(LOG_INFO, _("Regenerating symmetric key"));

              RAND_pseudo_bytes(myself->cipher_pktkey, myself->cipher_pktkeylength);
              send_key_changed(myself, NULL);
              keyexpires = time(NULL) + keylifetime;
            }
	}

      if(r > 0)
        {
          check_network_activity(&fset);

          /* local tap data */
          if(FD_ISSET(tap_fd, &fset))
	    handle_tap_input();
        }
    }
cp
}
