/*
    net.c -- most of the network code
    Copyright (C) 1998,1999,2000 Ivo Timmermans <itimmermans@bigfoot.com>,
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

    $Id: net.c,v 1.35.4.65 2000/11/04 17:09:10 guus Exp $
*/

#include "config.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/sockios.h>
#include <net/if.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/signal.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <syslog.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#ifdef HAVE_TUNTAP
#include LINUX_IF_TUN_H
#endif

#include <utils.h>
#include <xalloc.h>

#include "conf.h"
#include "connlist.h"
#include "meta.h"
#include "net.h"
#include "netutl.h"
#include "protocol.h"
#include "subnet.h"

#include "system.h"

int tap_fd = -1;
int taptype = TAP_TYPE_ETHERTAP;
int total_tap_in = 0;
int total_tap_out = 0;
int total_socket_in = 0;
int total_socket_out = 0;

config_t *upstreamcfg;
static int seconds_till_retry;

int keylifetime = 0;
int keyexpires = 0;

char *unknown = NULL;
char *interface_name = NULL;  /* Contains the name of the interface */

subnet_t mymac;

/*
  Execute the given script.
  This function doesn't really belong here.
*/
int execute_script(const char* name)
{
  char *scriptname;
  pid_t pid;
  char *s;

  if((pid = fork()) < 0)
    {
      syslog(LOG_ERR, _("System call `%s' failed: %m"),
	     "fork");
      return -1;
    }

  if(pid)
    {
      return 0;
    }

  /* Child here */

  asprintf(&scriptname, "%s/%s", confbase, name);
  asprintf(&s, "IFNAME=%s", interface_name);
  putenv(s);
  free(s);

  if(netname)
    {
      asprintf(&s, "NETNAME=%s", netname);
      putenv(s);
      free(s);
    }
  else
    {
      unsetenv("NETNAME");
    }

  if(chdir(confbase) < 0)
    {
      syslog(LOG_ERR, _("Couldn't chdir to `%s': %m"),
	     confbase);
    }
  
  execl(scriptname, NULL);
  /* No return on success */
  
  if(errno != ENOENT)  /* Ignore if the file does not exist */
    syslog(LOG_WARNING, _("Error executing `%s': %m"), scriptname);

  /* No need to free things */
  exit(0);
}

int xsend(conn_list_t *cl, vpn_packet_t *inpkt)
{
  vpn_packet_t outpkt;
  int outlen, outpad;
  EVP_CIPHER_CTX ctx;
cp
  outpkt.len = inpkt->len;
  
  /* Encrypt the packet */
  
  EVP_EncryptInit(&ctx, cl->cipher_pkttype, cl->cipher_pktkey, cl->cipher_pktkey + cl->cipher_pkttype->key_len);
  EVP_EncryptUpdate(&ctx, outpkt.data, &outlen, inpkt->data, inpkt->len);
  EVP_EncryptFinal(&ctx, outpkt.data + outlen, &outpad);
  outlen += outpad + 2;

/* Bypass
  outlen = outpkt.len + 2;
  memcpy(&outpkt, inpkt, outlen);
*/  

  if(debug_lvl >= DEBUG_TRAFFIC)
    syslog(LOG_ERR, _("Sending packet of %d bytes to %s (%s)"),
           outlen, cl->name, cl->hostname);

  total_socket_out += outlen;

  cl->want_ping = 1;

  if((send(cl->socket, (char *) &(outpkt.len), outlen, 0)) < 0)
    {
      syslog(LOG_ERR, _("Error sending packet to %s (%s): %m"),
             cl->name, cl->hostname);
      return -1;
    }
cp
  return 0;
}

int xrecv(vpn_packet_t *inpkt)
{
  vpn_packet_t outpkt;
  int outlen, outpad;
  EVP_CIPHER_CTX ctx;
cp
  outpkt.len = inpkt->len;

  /* Decrypt the packet */

  EVP_DecryptInit(&ctx, myself->cipher_pkttype, myself->cipher_pktkey, myself->cipher_pktkey + myself->cipher_pkttype->key_len);
  EVP_DecryptUpdate(&ctx, outpkt.data, &outlen, inpkt->data, inpkt->len + 8);
  EVP_DecryptFinal(&ctx, outpkt.data + outlen, &outpad);
  outlen += outpad;

/* Bypass
  outlen = outpkt.len+2;
  memcpy(&outpkt, inpkt, outlen);
*/
     
  if(debug_lvl >= DEBUG_TRAFFIC)
    syslog(LOG_ERR, _("Writing packet of %d bytes to tap device"),
           outpkt.len, outlen);

  /* Fix mac address */

  memcpy(outpkt.data, mymac.net.mac.address.x, 6);

  if(taptype == TAP_TYPE_TUNTAP)
    {
      if(write(tap_fd, outpkt.data, outpkt.len) < 0)
        syslog(LOG_ERR, _("Can't write to tun/tap device: %m"));
      else
        total_tap_out += outpkt.len;
    }
  else	/* ethertap */
    {
      if(write(tap_fd, outpkt.data - 2, outpkt.len + 2) < 0)
        syslog(LOG_ERR, _("Can't write to ethertap device: %m"));
      else
        total_tap_out += outpkt.len + 2;
    }
cp
  return 0;
}

/*
  add the given packet of size s to the
  queue q, be it the send or receive queue
*/
void add_queue(packet_queue_t **q, void *packet, size_t s)
{
  queue_element_t *e;
cp
  e = xmalloc(sizeof(*e));
  e->packet = xmalloc(s);
  memcpy(e->packet, packet, s);

  if(!*q)
    {
      *q = xmalloc(sizeof(**q));
      (*q)->head = (*q)->tail = NULL;
    }

  e->next = NULL;			/* We insert at the tail */

  if((*q)->tail)			/* Do we have a tail? */
    {
      (*q)->tail->next = e;
      e->prev = (*q)->tail;
    }
  else					/* No tail -> no head too */
    {
      (*q)->head = e;
      e->prev = NULL;
    }

  (*q)->tail = e;
cp
}

/* Remove a queue element */
void del_queue(packet_queue_t **q, queue_element_t *e)
{
cp
  free(e->packet);

  if(e->next)				/* There is a successor, so we are not tail */
    {
      if(e->prev)			/* There is a predecessor, so we are not head */
        {
          e->next->prev = e->prev;
          e->prev->next = e->next;
        }
      else				/* We are head */
        {
          e->next->prev = NULL;
          (*q)->head = e->next;
        }
    }
  else					/* We are tail (or all alone!) */
    {          
      if(e->prev)			/* We are not alone :) */
        {
          e->prev->next = NULL;
          (*q)->tail = e->prev;
        }
      else				/* Adieu */
        {
          free(*q);
          *q = NULL;
        }
    }
    
  free(e);
cp
}

/*
  flush a queue by calling function for
  each packet, and removing it when that
  returned a zero exit code
*/
void flush_queue(conn_list_t *cl, packet_queue_t **pq,
		 int (*function)(conn_list_t*,void*))
{
  queue_element_t *p, *next = NULL;
cp
  for(p = (*pq)->head; p != NULL; )
    {
      next = p->next;

      if(!function(cl, p->packet))
        del_queue(pq, p);
        
      p = next;
    }

  if(debug_lvl >= DEBUG_TRAFFIC)
    syslog(LOG_DEBUG, _("Queue flushed"));
cp
}

/*
  flush the send&recv queues
  void because nothing goes wrong here, packets
  remain in the queue if something goes wrong
*/
void flush_queues(conn_list_t *cl)
{
cp
  if(cl->sq)
    {
      if(debug_lvl >= DEBUG_TRAFFIC)
	syslog(LOG_DEBUG, _("Flushing send queue for %s (%s)"),
	       cl->name, cl->hostname);
      flush_queue(cl, &(cl->sq), xsend);
    }

  if(cl->rq)
    {
      if(debug_lvl >=  DEBUG_TRAFFIC)
	syslog(LOG_DEBUG, _("Flushing receive queue for %s (%s)"),
	       cl->name, cl->hostname);
      flush_queue(cl, &(cl->rq), xrecv);
    }
cp
}

/*
  send a packet to the given vpn ip.
*/
int send_packet(ip_t to, vpn_packet_t *packet)
{
  conn_list_t *cl;
  subnet_t *subnet;
cp
  if((subnet = lookup_subnet_ipv4(to)) == NULL)
    {
      if(debug_lvl >= DEBUG_TRAFFIC)
        {
          syslog(LOG_NOTICE, _("Trying to look up %d.%d.%d.%d in connection list failed!"),
	         IP_ADDR_V(to));
        }

      return -1;
    }

  cl = subnet->owner;
    
  if(cl == myself)
    {
      if(debug_lvl >= DEBUG_TRAFFIC)
        {
          syslog(LOG_NOTICE, _("Packet with destination %d.%d.%d.%d is looping back to us!"),
	         IP_ADDR_V(to));
        }

      return -1;
    }

  /* If we ourselves have indirectdata flag set, we should send only to our uplink! */

  /* FIXME - check for indirection and reprogram it The Right Way(tm) this time. */
  
  if(!cl->status.dataopen)
    if(setup_vpn_connection(cl) < 0)
      {
        syslog(LOG_ERR, _("Could not open UDP connection to %s (%s)"),
	       cl->name, cl->hostname);
        return -1;
      }
      
  if(!cl->status.validkey)
    {
/* FIXME: Don't queue until everything else is fixed.
      if(debug_lvl >= DEBUG_TRAFFIC)
	syslog(LOG_INFO, _("No valid key known yet for %s (%s), queueing packet"),
	       cl->name, cl->hostname);
      add_queue(&(cl->sq), packet, packet->len + 2);
*/
      if(!cl->status.waitingforkey)
	send_req_key(myself, cl);			/* Keys should be sent to the host running the tincd */
      return 0;
    }

  if(!cl->status.active)
    {
/* FIXME: Don't queue until everything else is fixed.
      if(debug_lvl >= DEBUG_TRAFFIC)
	syslog(LOG_INFO, _("%s (%s) is not ready, queueing packet"),
	       cl->name, cl->hostname);
      add_queue(&(cl->sq), packet, packet->len + 2);
*/
      return 0; /* We don't want to mess up, do we? */
    }

  /* can we send it? can we? can we? huh? */
cp
  return xsend(cl, packet);
}

/*
  open the local ethertap device
*/
int setup_tap_fd(void)
{
  int nfd;
  const char *tapfname;
  config_t const *cfg;
  struct ifreq ifr;

cp  
  if((cfg = get_config_val(config, tapdevice)))
    tapfname = cfg->data.ptr;
  else
#ifdef HAVE_TUNTAP
    tapfname = "/dev/misc/net/tun";
#else
    tapfname = "/dev/tap0";
#endif
cp
  if((nfd = open(tapfname, O_RDWR | O_NONBLOCK)) < 0)
    {
      syslog(LOG_ERR, _("Could not open %s: %m"), tapfname);
      return -1;
    }
cp
  tap_fd = nfd;

  /* Set default MAC address for ethertap devices */
  
  taptype = TAP_TYPE_ETHERTAP;
  mymac.type = SUBNET_MAC;
  mymac.net.mac.address.x[0] = 0xfe;
  mymac.net.mac.address.x[1] = 0xfd;
  mymac.net.mac.address.x[2] = 0x00;
  mymac.net.mac.address.x[3] = 0x00;
  mymac.net.mac.address.x[4] = 0x00;
  mymac.net.mac.address.x[5] = 0x00;

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

  /* Add name of network interface to environment (for scripts) */

  ioctl(tap_fd, SIOCGIFNAME, (void *) &ifr);
  interface_name = xmalloc(strlen(ifr.ifr_name));
  strcpy(interface_name, ifr.ifr_name);
  
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
  const int one = 1;
  config_t const *cfg;
cp
  if((nfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0)
    {
      syslog(LOG_ERR, _("Creating metasocket failed: %m"));
      return -1;
    }

  if(setsockopt(nfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)))
    {
      syslog(LOG_ERR, _("System call `%s' failed: %m"),
	     "setsockopt");
      return -1;
    }

  if(setsockopt(nfd, SOL_SOCKET, SO_KEEPALIVE, &one, sizeof(one)))
    {
      syslog(LOG_ERR, _("System call `%s' failed: %m"),
	     "setsockopt");
      return -1;
    }

  flags = fcntl(nfd, F_GETFL);
  if(fcntl(nfd, F_SETFL, flags | O_NONBLOCK) < 0)
    {
      syslog(LOG_ERR, _("System call `%s' failed: %m"),
	     "fcntl");
      return -1;
    }

  if((cfg = get_config_val(config, interface)))
    {
      if(setsockopt(nfd, SOL_SOCKET, SO_KEEPALIVE, cfg->data.ptr, strlen(cfg->data.ptr)))
        {
          syslog(LOG_ERR, _("Unable to bind listen socket to interface %s: %m"), cfg->data.ptr);
          return -1;
        }
    }

  memset(&a, 0, sizeof(a));
  a.sin_family = AF_INET;
  a.sin_port = htons(port);
  
  if((cfg = get_config_val(config, interfaceip)))
    a.sin_addr.s_addr = htonl(cfg->data.ip->address);
  else
    a.sin_addr.s_addr = htonl(INADDR_ANY);

  if(bind(nfd, (struct sockaddr *)&a, sizeof(struct sockaddr)))
    {
      syslog(LOG_ERR, _("Can't bind to port %hd/tcp: %m"), port);
      return -1;
    }

  if(listen(nfd, 3))
    {
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
      syslog(LOG_ERR, _("Creating socket failed: %m"));
      return -1;
    }

  if(setsockopt(nfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)))
    {
      syslog(LOG_ERR, _("System call `%s' failed: %m"),
	     "setsockopt");
      return -1;
    }

  flags = fcntl(nfd, F_GETFL);
  if(fcntl(nfd, F_SETFL, flags | O_NONBLOCK) < 0)
    {
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
      syslog(LOG_ERR, _("Can't bind to port %hd/udp: %m"), port);
      return -1;
    }
cp
  return nfd;
}

/*
  setup an outgoing meta (tcp) socket
*/
int setup_outgoing_meta_socket(conn_list_t *cl)
{
  int flags;
  struct sockaddr_in a;
  config_t const *cfg;
cp
  if(debug_lvl >= DEBUG_CONNECTIONS)
    syslog(LOG_INFO, _("Trying to connect to %s"), cl->hostname);

  if((cfg = get_config_val(cl->config, port)) == NULL)
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

  a.sin_family = AF_INET;
  a.sin_port = htons(cl->port);
  a.sin_addr.s_addr = htonl(cl->address);

  if(connect(cl->meta_socket, (struct sockaddr *)&a, sizeof(a)) == -1)
    {
      syslog(LOG_ERR, _("%s port %hd: %m"), cl->hostname, cl->port);
      return -1;
    }

  flags = fcntl(cl->meta_socket, F_GETFL);
  if(fcntl(cl->meta_socket, F_SETFL, flags | O_NONBLOCK) < 0)
    {
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
  setup an outgoing connection. It's not
  necessary to also open an udp socket as
  well, because the other host will initiate
  an authentication sequence during which
  we will do just that.
*/
int setup_outgoing_connection(char *name)
{
  conn_list_t *ncn;
  struct hostent *h;
  config_t const *cfg;
cp
  if(check_id(name))
    {
      syslog(LOG_ERR, _("Invalid name for outgoing connection"));
      return -1;
    }

  ncn = new_conn_list();
  asprintf(&ncn->name, "%s", name);
    
  if(read_host_config(ncn))
    {
      syslog(LOG_ERR, _("Error reading host configuration file for %s"));
      free_conn_list(ncn);
      return -1;
    }
    
  if(!(cfg = get_config_val(ncn->config, address)))
    {
      syslog(LOG_ERR, _("No address specified for %s"));
      free_conn_list(ncn);
      return -1;
    }
    
  if(!(h = gethostbyname(cfg->data.ptr)))
    {
      syslog(LOG_ERR, _("Error looking up `%s': %m"), cfg->data.ptr);
      free_conn_list(ncn);
      return -1;
    }

  ncn->address = ntohl(*((ip_t*)(h->h_addr_list[0])));
  ncn->hostname = hostlookup(htonl(ncn->address));
  
  if(setup_outgoing_meta_socket(ncn) < 0)
    {
      syslog(LOG_ERR, _("Could not set up a meta connection to %s"),
             ncn->hostname);
      free_conn_list(ncn);
      return -1;
    }

  ncn->status.outgoing = 1;
  ncn->buffer = xmalloc(MAXBUFSIZE);
  ncn->buflen = 0;
  ncn->last_ping_time = time(NULL);
  ncn->want_ping = 0;

  conn_list_add(ncn);

  send_id(ncn);
cp
  return 0;
}

/*
  Configure conn_list_t myself and set up the local sockets (listen only)
*/
int setup_myself(void)
{
  config_t const *cfg;
  subnet_t *net;
cp
  myself = new_conn_list();

  asprintf(&myself->hostname, "MYSELF"); /* FIXME? Do hostlookup on ourselves? */
  myself->flags = 0;
  myself->protocol_version = PROT_CURRENT;

  if(!(cfg = get_config_val(config, tincname))) /* Not acceptable */
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
  if(!(cfg = get_config_val(config, privatekey)))
    {
      syslog(LOG_ERR, _("Private key for tinc daemon required!"));
      return -1;
    }
  else
    {
      myself->rsa_key = RSA_new();
      BN_hex2bn(&myself->rsa_key->d, cfg->data.ptr);
      BN_hex2bn(&myself->rsa_key->e, "FFFF");
    }

  if(read_host_config(myself))
    {
      syslog(LOG_ERR, _("Cannot open host configuration file for myself!"));
      return -1;
    }
cp  
  if(!(cfg = get_config_val(myself->config, publickey)))
    {
      syslog(LOG_ERR, _("Public key for tinc daemon required!"));
      return -1;
    }
  else
    {
      BN_hex2bn(&myself->rsa_key->n, cfg->data.ptr);
    }
/*
  if(RSA_check_key(myself->rsa_key) != 1)
    {
      syslog(LOG_ERR, _("Invalid public/private keypair!"));
      return -1;
    }
*/
  if(!(cfg = get_config_val(myself->config, port)))
    myself->port = 655;
  else
    myself->port = cfg->data.val;

  if((cfg = get_config_val(myself->config, indirectdata)))
    if(cfg->data.val == stupid_true)
      myself->flags |= EXPORTINDIRECTDATA;

  if((cfg = get_config_val(myself->config, tcponly)))
    if(cfg->data.val == stupid_true)
      myself->flags |= TCPONLY;

/* Read in all the subnets specified in the host configuration file */

  for(cfg = myself->config; (cfg = get_config_val(cfg, subnet)); cfg = cfg->next)
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
    
  if((myself->meta_socket = setup_listen_meta_socket(myself->port)) < 0)
    {
      syslog(LOG_ERR, _("Unable to set up a listening socket!"));
      return -1;
    }

  if((myself->socket = setup_vpn_in_socket(myself->port)) < 0)
    {
      syslog(LOG_ERR, _("Unable to set up an incoming vpn data socket!"));
      close(myself->meta_socket);
      return -1;
    }

  /* Generate packet encryption key */

  myself->cipher_pkttype = EVP_bf_cfb();

  myself->cipher_pktkeylength = myself->cipher_pkttype->key_len + myself->cipher_pkttype->iv_len;

  myself->cipher_pktkey = (char *)xmalloc(myself->cipher_pktkeylength);
  RAND_bytes(myself->cipher_pktkey, myself->cipher_pktkeylength);

  if(!(cfg = get_config_val(config, keyexpire)))
    keylifetime = 3600;
  else
    keylifetime = cfg->data.val;
    
  keyexpires = time(NULL) + keylifetime;

  /* Activate ourselves */
  
  myself->status.active = 1;

  syslog(LOG_NOTICE, _("Ready: listening on port %hd"), myself->port);
cp
  return 0;
}

RETSIGTYPE
sigalrm_handler(int a)
{
  config_t const *cfg;
cp
  cfg = get_config_val(upstreamcfg, connectto);

  if(!cfg && upstreamcfg == config)
    /* No upstream IP given, we're listen only. */
    return;

  while(cfg)
    {
      upstreamcfg = cfg->next;
      if(!setup_outgoing_connection(cfg->data.ptr))   /* function returns 0 when there are no problems */
        {
          signal(SIGALRM, SIG_IGN);
          return;
        }
      cfg = get_config_val(upstreamcfg, connectto); /* Or else we try the next ConnectTo line */
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
  if((cfg = get_config_val(config, pingtimeout)) == NULL)
    timeout = 5;
  else
    timeout = cfg->data.val;

  if(setup_tap_fd() < 0)
    return -1;

  if(setup_myself() < 0)
    return -1;

  /* Run tinc-up script to further initialize the tap interface */
  execute_script("tinc-up");
  
  if(!(cfg = get_config_val(config, connectto)))
    /* No upstream IP given, we're listen only. */
    return 0;

  while(cfg)
    {
      upstreamcfg = cfg->next;
      if(!setup_outgoing_connection(cfg->data.ptr))   /* function returns 0 when there are no problems */
        return 0;
      cfg = get_config_val(upstreamcfg, connectto); /* Or else we try the next ConnectTo line */
    }
    
  signal(SIGALRM, sigalrm_handler);
  upstreamcfg = config;
  seconds_till_retry = MAXTIMEOUT;
  syslog(LOG_NOTICE, _("Trying to re-establish outgoing connection in %d seconds"), seconds_till_retry);
  alarm(seconds_till_retry);
cp
  return 0;
}

/*
  close all open network connections
*/
void close_network_connections(void)
{
  conn_list_t *p;
cp
  for(p = conn_list; p != NULL; p = p->next)
    {
      p->status.active = 0;
      terminate_connection(p);
    }

  if(myself)
    if(myself->status.active)
      {
	close(myself->meta_socket);
	close(myself->socket);
        free_conn_list(myself);
        myself = NULL;
      }

  close(tap_fd);

  /* Execute tinc-down script right after shutting down the interface */
  execute_script("tinc-down");

  destroy_conn_list();

  syslog(LOG_NOTICE, _("Terminating"));
cp
  return;
}

/*
  create a data (udp) socket
*/
int setup_vpn_connection(conn_list_t *cl)
{
  int nfd, flags;
  struct sockaddr_in a;
cp
  if(debug_lvl >= DEBUG_TRAFFIC)
    syslog(LOG_DEBUG, _("Opening UDP socket to %s"), cl->hostname);

  nfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if(nfd == -1)
    {
      syslog(LOG_ERR, _("Creating UDP socket failed: %m"));
      return -1;
    }

  a.sin_family = AF_INET;
  a.sin_port = htons(cl->port);
  a.sin_addr.s_addr = htonl(cl->address);

  if(connect(nfd, (struct sockaddr *)&a, sizeof(a)) == -1)
    {
      syslog(LOG_ERR, _("Connecting to %s port %d failed: %m"),
	     cl->hostname, cl->port);
      return -1;
    }

  flags = fcntl(nfd, F_GETFL);
  if(fcntl(nfd, F_SETFL, flags | O_NONBLOCK) < 0)
    {
      syslog(LOG_ERR, _("This is a bug: %s:%d: %d:%m %s (%s)"), __FILE__, __LINE__, nfd,
             cl->name, cl->hostname);
      return -1;
    }

  cl->socket = nfd;
  cl->status.dataopen = 1;
cp
  return 0;
}

/*
  handle an incoming tcp connect call and open
  a connection to it.
*/
conn_list_t *create_new_connection(int sfd)
{
  conn_list_t *p;
  struct sockaddr_in ci;
  int len = sizeof(ci);
cp
  p = new_conn_list();

  if(getpeername(sfd, &ci, &len) < 0)
    {
      syslog(LOG_ERR, _("System call `%s' failed: %m"),
	     "getpeername");
      return NULL;
    }

  p->name = unknown;
  p->address = ntohl(ci.sin_addr.s_addr);
  p->hostname = hostlookup(ci.sin_addr.s_addr);
  p->meta_socket = sfd;
  p->status.meta = 1;
  p->buffer = xmalloc(MAXBUFSIZE);
  p->buflen = 0;
  p->last_ping_time = time(NULL);
  p->want_ping = 0;
  
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
  conn_list_t *p;
cp
  FD_ZERO(fs);

  for(p = conn_list; p != NULL; p = p->next)
    {
      if(p->status.meta)
	FD_SET(p->meta_socket, fs);
      if(p->status.dataopen)
	FD_SET(p->socket, fs);
    }

  FD_SET(myself->meta_socket, fs);
  FD_SET(myself->socket, fs);
  FD_SET(tap_fd, fs);
cp
}

/*
  receive incoming data from the listening
  udp socket and write it to the ethertap
  device after being decrypted
*/
int handle_incoming_vpn_data()
{
  vpn_packet_t pkt;
  int x, l = sizeof(x);
  struct sockaddr from;
  int lenin;
  socklen_t fromlen = sizeof(from);
cp
  if(getsockopt(myself->socket, SOL_SOCKET, SO_ERROR, &x, &l) < 0)
    {
      syslog(LOG_ERR, _("This is a bug: %s:%d: %d:%m"),
	     __FILE__, __LINE__, myself->socket);
      return -1;
    }
  if(x)
    {
      syslog(LOG_ERR, _("Incoming data socket error: %s"), strerror(x));
      return -1;
    }

  if((lenin = recvfrom(myself->socket, (char *) &(pkt.len), MTU, 0, &from, &fromlen)) <= 0)
    {
      syslog(LOG_ERR, _("Receiving packet failed: %m"));
      return -1;
    }

  if(debug_lvl >= DEBUG_TRAFFIC)
    {
      syslog(LOG_DEBUG, _("Received packet of %d bytes"), lenin);
    } 

cp
  return xrecv(&pkt);
}

/*
  terminate a connection and notify the other
  end before closing the sockets
*/
void terminate_connection(conn_list_t *cl)
{
  conn_list_t *p;
  subnet_t *s;
cp
  if(cl->status.remove)
    return;

  cl->status.remove = 1;

  if(debug_lvl >= DEBUG_CONNECTIONS)
    syslog(LOG_NOTICE, _("Closing connection with %s (%s)"),
           cl->name, cl->hostname);
 
  if(cl->socket)
    close(cl->socket);
  if(cl->status.meta)
    close(cl->meta_socket);

cp
  /* Find all connections that were lost because they were behind cl
     (the connection that was dropped). */

  if(cl->status.meta)
    for(p = conn_list; p != NULL; p = p->next)
      if((p->nexthop == cl) && (p != cl))
        terminate_connection(p);	/* Sounds like recursion, but p does not have a meta connection :) */

  /* Inform others of termination if it was still active */

  if(cl->status.active)
    for(p = conn_list; p != NULL; p = p->next)
      if(p->status.meta && p->status.active && p!=cl)
        send_del_host(p, cl);

  /* Remove the associated subnets */

  for(s = cl->subnets; s; s = s->next)
    subnet_del(s);

  /* Check if this was our outgoing connection */
    
  if(cl->status.outgoing && cl->status.active)
    {
      signal(SIGALRM, sigalrm_handler);
      seconds_till_retry = 5;
      alarm(seconds_till_retry);
      syslog(LOG_NOTICE, _("Trying to re-establish outgoing connection in 5 seconds"));
    }

  /* Inactivate */

  cl->status.active = 0;
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
int check_dead_connections(void)
{
  conn_list_t *p;
  time_t now;
cp
  now = time(NULL);
  for(p = conn_list; p != NULL; p = p->next)
    {
      if(p->status.active && p->status.meta)
	{
          if(p->last_ping_time + timeout < now)
            {
              if(p->status.pinged && !p->status.got_pong)
                {
                  if(debug_lvl >= DEBUG_PROTOCOL)
  	            syslog(LOG_INFO, _("%s (%s) didn't respond to PING"),
		           p->name, p->hostname);
	          p->status.timeout = 1;
	          terminate_connection(p);
                }
              else if(p->want_ping)
                {
                  send_ping(p);
                  p->last_ping_time = now;
                  p->status.pinged = 1;
                  p->status.got_pong = 0;
                }
            }
	}
    }
cp
  return 0;
}

/*
  accept a new tcp connect and create a
  new connection
*/
int handle_new_meta_connection()
{
  conn_list_t *ncn;
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

  conn_list_add(ncn);
cp
  return 0;
}

/*
  check all connections to see if anything
  happened on their sockets
*/
void check_network_activity(fd_set *f)
{
  conn_list_t *p;
  int x, l = sizeof(x);
cp
  for(p = conn_list; p != NULL; p = p->next)
    {
      if(p->status.remove)
	continue;

      if(p->status.dataopen)
	if(FD_ISSET(p->socket, f))
	  {
	    /*
	      The only thing that can happen to get us here is apparently an
	      error on this outgoing(!) UDP socket that isn't immediate (i.e.
	      something that will not trigger an error directly on send()).
	      I've once got here when it said `No route to host'.
	    */
	    getsockopt(p->socket, SOL_SOCKET, SO_ERROR, &x, &l);
	    syslog(LOG_ERR, _("Outgoing data socket error for %s (%s): %s"),
                   p->name, p->hostname, strerror(x));
	    terminate_connection(p);
	    return;
	  }  

      if(p->status.meta)
	if(FD_ISSET(p->meta_socket, f))
	  if(receive_meta(p) < 0)
	    {
	      terminate_connection(p);
	      return;
	    } 
    }
  
  if(FD_ISSET(myself->socket, f))
    handle_incoming_vpn_data();

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

  total_tap_in += lenin;

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

  send_packet(ntohl(*((unsigned long*)(&vp.data[30]))), &vp);
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

      prune_conn_list();
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
              exit(0);
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
                
              RAND_bytes(myself->cipher_pktkey, myself->cipher_pktkeylength);
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
