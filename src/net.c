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

    $Id: net.c,v 1.35.4.32 2000/09/26 14:06:04 guus Exp $
*/

#include "config.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
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

#include <cipher.h>
#include <utils.h>
#include <xalloc.h>

#include "conf.h"
#include "encr.h"
#include "net.h"
#include "netutl.h"
#include "protocol.h"
#include "meta.h"

#include "system.h"

int tap_fd = -1;

int total_tap_in = 0;
int total_tap_out = 0;
int total_socket_in = 0;
int total_socket_out = 0;

int upstreamindex = 0;
static int seconds_till_retry;

/* The global list of existing connections */
conn_list_t *conn_list = NULL;
conn_list_t *myself = NULL;

/*
  strip off the MAC adresses of an ethernet frame
*/
void strip_mac_addresses(vpn_packet_t *p)
{
  unsigned char tmp[MAXSIZE];
cp
  memcpy(tmp, p->data, p->len);
  p->len -= 12;
  memcpy(p->data, &tmp[12], p->len);
cp
}

/*
  reassemble MAC addresses
*/
void add_mac_addresses(vpn_packet_t *p)
{
  unsigned char tmp[MAXSIZE];
cp
  memcpy(&tmp[12], p->data, p->len);
  p->len += 12;
  tmp[0] = tmp[6] = 0xfe;
  tmp[1] = tmp[7] = 0xfd;
  *((ip_t*)(&tmp[2])) = (ip_t)(htonl(myself->vpn_ip));
  *((ip_t*)(&tmp[8])) = *((ip_t*)(&tmp[26]));
  memcpy(p->data, &tmp[0], p->len);
cp
}

int xsend(conn_list_t *cl, void *packet)
{
  real_packet_t rp;
cp
  do_encrypt((vpn_packet_t*)packet, &rp, cl->datakey);
  rp.from = htonl(myself->vpn_ip);
  rp.data.len = htons(rp.data.len);
  rp.len = htons(rp.len);

  if(debug_lvl > 3)
    syslog(LOG_ERR, _("Sending packet of %d bytes to %s (%s)"),
           ntohs(rp.len), cl->name, cl->hostname);

  total_socket_out += ntohs(rp.len);

  cl->want_ping = 1;

  if((cl->flags | myself->flags) & TCPONLY)
      return send_tcppacket(cl, (void*)&rp, ntohs(rp.len));

  if((send(cl->socket, (char*)&rp, ntohs(rp.len), 0)) < 0)
    {
      syslog(LOG_ERR, _("Error sending packet to %s (%s): %m"),
             cl->name, cl->hostname);
      return -1;
    }
cp
  return 0;
}

int xrecv(conn_list_t *cl, void *packet)
{
  vpn_packet_t vp;
  int lenin;
cp
  do_decrypt((real_packet_t*)packet, &vp, cl->datakey);
  add_mac_addresses(&vp);

  if(debug_lvl > 3)
    syslog(LOG_ERR, _("Receiving packet of %d bytes from %s (%s)"),
           ((real_packet_t*)packet)->len, cl->name, cl->hostname);

  if((lenin = write(tap_fd, &vp, vp.len + sizeof(vp.len))) < 0)
    syslog(LOG_ERR, _("Can't write to tap device: %m"));
  else
    total_tap_out += lenin;

  cl->want_ping = 0;
  cl->last_ping_time = time(NULL);
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

  if(debug_lvl > 3)
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
      if(debug_lvl > 3)
	syslog(LOG_DEBUG, _("Flushing send queue for %s (%s)"),
	       cl->name, cl->hostname);
      flush_queue(cl, &(cl->sq), xsend);
    }

  if(cl->rq)
    {
      if(debug_lvl > 3)
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
cp
  if((cl = lookup_conn(to)) == NULL)
    {
      if(debug_lvl > 3)
        {
          syslog(LOG_NOTICE, _("Trying to look up %d.%d.%d.%d in connection list failed!"),
	         IP_ADDR_V(to));
        }

      return -1;
   }
    
  /* If we ourselves have indirectdata flag set, we should send only to our uplink! */
  
  /* The next few lines will be obsoleted, if we are going indirect, matching subnet_t
     should point to only our uplink as the recepient
  */

  if(myself->flags & EXPORTINDIRECTDATA)
    {
      for(cl = conn_list; cl != NULL && !cl->status.outgoing; cl = cl->next);
      if(!cl)
        { /* No open outgoing connection has been found. */
	  if(debug_lvl > 3)
	    syslog(LOG_NOTICE, _("There is no remote host I can send this packet to!"));
          return -1;
        }
    }
  else

  /* If indirectdata flag is set for the destination we just looked up,
   * then real_ip is actually the vpn_ip of the gateway tincd
   * it is behind.
   */
   
  if(cl->flags & INDIRECTDATA)
    {
      if(debug_lvl > 3)
        syslog(LOG_NOTICE, _("Indirect packet to %s via %s"),
               cl->name, cl->hostname);
      if((cl = lookup_conn(cl->real_ip)) == NULL)
        {
          if(debug_lvl > 3)
              syslog(LOG_NOTICE, _("Indirect look up %d.%d.%d.%d in connection list failed!"), IP_ADDR_V(to));
            
          /* Gateway tincd dead? Should we kill it? (GS) */

          return -1;
        }
      if(cl->flags & INDIRECTDATA)  /* This should not happen */
        {
          if(debug_lvl > 3)
              syslog(LOG_NOTICE, _("Double indirection for %d.%d.%d.%d"), IP_ADDR_V(to));
          return -1;        
        }
    }            

  if(my_key_expiry <= time(NULL))
    regenerate_keys();

  if(!cl->status.dataopen)
    if(setup_vpn_connection(cl) < 0)
      {
        syslog(LOG_ERR, _("Could not open UDP connection to %s (%s)"),
	       cl->name, cl->hostname);
        return -1;
      }
      
  if(!cl->status.validkey)
    {
      if(debug_lvl > 3)
	syslog(LOG_INFO, _("%s (%s) has no valid key, queueing packet"),
	       cl->name, cl->hostname);
      add_queue(&(cl->sq), packet, packet->len + 2);
      if(!cl->status.waitingforkey)
	send_key_request(cl->vpn_ip);			/* Keys should be sent to the host running the tincd */
      return 0;
    }

  if(!cl->status.active)
    {
      if(debug_lvl > 3)
	syslog(LOG_INFO, _("%s (%s) is not ready, queueing packet"),
	       cl->name, cl->hostname);
      add_queue(&(cl->sq), packet, packet->len + 2);
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
cp  
  if((cfg = get_config_val(tapdevice)) == NULL)
    tapfname = "/dev/tap0";
  else
    tapfname = cfg->data.ptr;

  if((nfd = open(tapfname, O_RDWR | O_NONBLOCK)) < 0)
    {
      syslog(LOG_ERR, _("Could not open %s: %m"), tapfname);
      return -1;
    }

  tap_fd = nfd;
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
      syslog(LOG_ERR, _("setsockopt: %m"));
      return -1;
    }

  if(setsockopt(nfd, SOL_SOCKET, SO_KEEPALIVE, &one, sizeof(one)))
    {
      syslog(LOG_ERR, _("setsockopt: %m"));
      return -1;
    }

  flags = fcntl(nfd, F_GETFL);
  if(fcntl(nfd, F_SETFL, flags | O_NONBLOCK) < 0)
    {
      syslog(LOG_ERR, _("fcntl: %m"));
      return -1;
    }

  if((cfg = get_config_val(interface)))
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
  
  if((cfg = get_config_val(interfaceip)))
    a.sin_addr.s_addr = htonl(cfg->data.ip->ip);
  else
    a.sin_addr.s_addr = htonl(INADDR_ANY);

  if(bind(nfd, (struct sockaddr *)&a, sizeof(struct sockaddr)))
    {
      syslog(LOG_ERR, _("Can't bind to port %hd/tcp: %m"), port);
      return -1;
    }

  if(listen(nfd, 3))
    {
      syslog(LOG_ERR, _("listen: %m"));
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
      syslog(LOG_ERR, _("setsockopt: %m"));
      return -1;
    }

  flags = fcntl(nfd, F_GETFL);
  if(fcntl(nfd, F_SETFL, flags | O_NONBLOCK) < 0)
    {
      syslog(LOG_ERR, _("fcntl: %m"));
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
  if(debug_lvl > 0)
    syslog(LOG_INFO, _("Trying to connect to %s"), cl->hostname);

  if((cfg = get_config_val(upstreamport)) == NULL)
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
  a.sin_addr.s_addr = htonl(cl->real_ip);

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

  if(debug_lvl > 0)
    syslog(LOG_INFO, _("Connected to %s port %hd"),
         cl->hostname, cl->port);
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
int setup_outgoing_connection(char *hostname)
{
  conn_list_t *ncn;
  struct hostent *h;
cp
  if(!(h = gethostbyname(hostname)))
    {
      syslog(LOG_ERR, _("Error looking up `%s': %m"), hostname);
      return -1;
    }

  ncn = new_conn_list();
  ncn->real_ip = ntohl(*((ip_t*)(h->h_addr_list[0])));
  ncn->hostname = hostlookup(htonl(ncn->real_ip));
  
  if(setup_outgoing_meta_socket(ncn) < 0)
    {
      syslog(LOG_ERR, _("Could not set up a meta connection to %s"),
             ncn->hostname);
      free_conn_element(ncn);
      return -1;
    }

  ncn->status.meta = 1;
  ncn->status.outgoing = 1;
  ncn->next = conn_list;
  conn_list = ncn;
cp
  return 0;
}

/*
  set up the local sockets (listen only)
*/
int setup_myself(void)
{
  config_t const *cfg;
cp
  myself = new_conn_list();

  if(!(cfg = get_config_val(myvpnip)))
    {
      syslog(LOG_ERR, _("No value for my VPN IP given"));
      return -1;
    }

  myself->vpn_ip = cfg->data.ip->ip;
  myself->hostname = hostlookup(htonl(myself->vpn_ip));
  myself->vpn_mask = cfg->data.ip->mask;
  myself->flags = 0;

  if(!(cfg = get_config_val(tincname)))
    asprintf(&(myself->name), IP_ADDR_S, IP_ADDR_V(myself->vpn_ip));
  else
    myself->name = (char*)cfg->data.val;
  
  if(!(cfg = get_config_val(listenport)))
    myself->port = 655;
  else
    myself->port = cfg->data.val;

  if((cfg = get_config_val(indirectdata)))
    if(cfg->data.val == stupid_true)
      myself->flags |= EXPORTINDIRECTDATA;

  if((cfg = get_config_val(tcponly)))
    if(cfg->data.val == stupid_true)
      myself->flags |= TCPONLY;

  if((myself->meta_socket = setup_listen_meta_socket(myself->port)) < 0)
    {
      syslog(LOG_ERR, _("Unable to set up a listening socket"));
      return -1;
    }

  if((myself->socket = setup_vpn_in_socket(myself->port)) < 0)
    {
      syslog(LOG_ERR, _("Unable to set up an incoming vpn data socket"));
      close(myself->meta_socket);
      return -1;
    }

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
  cfg = get_next_config_val(upstreamip, upstreamindex++);

  while(cfg)
    {
      if(!setup_outgoing_connection(cfg->data.ptr))   /* function returns 0 when there are no problems */
        {
          signal(SIGALRM, SIG_IGN);
          return;
        }
      cfg = get_next_config_val(upstreamip, upstreamindex++); /* Or else we try the next ConnectTo line */
    }

  signal(SIGALRM, sigalrm_handler);
  upstreamindex = 0;
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
  if((cfg = get_config_val(pingtimeout)) == NULL)
    timeout = 5;
  else
    timeout = cfg->data.val;

  if(setup_tap_fd() < 0)
    return -1;

  if(setup_myself() < 0)
    return -1;

  if((cfg = get_next_config_val(upstreamip, upstreamindex++)) == NULL)
    /* No upstream IP given, we're listen only. */
    return 0;

  while(cfg)
    {
      if(!setup_outgoing_connection(cfg->data.ptr))   /* function returns 0 when there are no problems */
        return 0;
      cfg = get_next_config_val(upstreamip, upstreamindex++); /* Or else we try the next ConnectTo line */
    }
    
  signal(SIGALRM, sigalrm_handler);
  upstreamindex = 0;
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
      if(p->status.dataopen)
	{
	  shutdown(p->socket, 0); /* No more receptions */
	  close(p->socket);
	}
      if(p->status.meta)
	{
	  send_termreq(p);
	  shutdown(p->meta_socket, 0); /* No more receptions */
          close(p->meta_socket);
        }
    }

  if(myself)
    if(myself->status.active)
      {
	close(myself->meta_socket);
	close(myself->socket);
      }

  close(tap_fd);
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
  if(debug_lvl > 0)
    syslog(LOG_DEBUG, _("Opening UDP socket to %s"), cl->hostname);

  nfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if(nfd == -1)
    {
      syslog(LOG_ERR, _("Creating UDP socket failed: %m"));
      return -1;
    }

  a.sin_family = AF_INET;
  a.sin_port = htons(cl->port);
  a.sin_addr.s_addr = htonl(cl->real_ip);

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
      syslog(LOG_ERR, _("Error: getpeername: %m"));
      return NULL;
    }

  p->real_ip = ntohl(ci.sin_addr.s_addr);
  p->hostname = hostlookup(ci.sin_addr.s_addr);
  p->meta_socket = sfd;
  p->status.meta = 1;
  p->buflen = 0;
  p->last_ping_time = time(NULL);
  p->want_ping = 0;
  
  if(debug_lvl > 0)
    syslog(LOG_NOTICE, _("Connection from %s port %d"),
         p->hostname, htons(ci.sin_port));

  if(send_basic_info(p) < 0)
    {
      free_conn_element(p);
      return NULL;
    }
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
int handle_incoming_vpn_data(conn_list_t *cl)
{
  real_packet_t rp;
  int lenin;
  int x, l = sizeof(x);
  conn_list_t *f;
cp
  if(getsockopt(cl->socket, SOL_SOCKET, SO_ERROR, &x, &l) < 0)
    {
      syslog(LOG_ERR, _("This is a bug: %s:%d: %d:%m %s (%s)"),
	     __FILE__, __LINE__, cl->socket,
             cl->name, cl->hostname);
      return -1;
    }
  if(x)
    {
      syslog(LOG_ERR, _("Incoming data socket error for %s (%s): %s"),
             cl->name, cl->hostname, strerror(x));
      return -1;
    }

  rp.len = -1;
  lenin = recvfrom(cl->socket, &rp, MTU, 0, NULL, NULL);
  if(lenin <= 0)
    {
      syslog(LOG_ERR, _("Receiving packet from %s (%s) failed: %m"),
	     cl->name, cl->hostname);
      return -1;
    }
  total_socket_in += lenin;

  rp.data.len = ntohs(rp.data.len);
  rp.len = ntohs(rp.len);
  rp.from = ntohl(rp.from);

  if(rp.len >= 0)
    {
      f = lookup_conn(rp.from);
      if(!f)
	{
	  syslog(LOG_ERR, _("Got packet from %s (%s) with unknown origin %d.%d.%d.%d?"),
		 cl->name, cl->hostname, IP_ADDR_V(rp.from));
	  return -1;
	}

      if(f->status.validkey)
	xrecv(f, &rp);
      else
	{
	  add_queue(&(f->rq), &rp, rp.len);
	  if(!cl->status.waitingforkey)
	    send_key_request(rp.from);
	}

      if(my_key_expiry <= time(NULL))
	regenerate_keys();
    }
cp
  return 0;
}

/*
  terminate a connection and notify the other
  end before closing the sockets
*/
void terminate_connection(conn_list_t *cl)
{
  conn_list_t *p;

cp
  if(cl->status.remove)
    return;

  if(debug_lvl > 0)
    syslog(LOG_NOTICE, _("Closing connection with %s (%s)"),
           cl->name, cl->hostname);

  if(cl->status.timeout)
    send_timeout(cl);
/*  else if(!cl->status.termreq)
    send_termreq(cl);
 */
 
  if(cl->socket)
    close(cl->socket);
  if(cl->status.meta)
    close(cl->meta_socket);

  cl->status.remove = 1;

  /* If this cl isn't active, don't send any DEL_HOSTs. */
  if(cl->status.active)
    notify_others(cl,NULL,send_del_host);
    
cp
  /* Find all connections that were lost because they were behind cl
     (the connection that was dropped). */
  if(cl->status.meta)
    for(p = conn_list; p != NULL; p = p->next)
      {
        if((p->nexthop == cl) && (p != cl))
          {
            if(cl->status.active && p->status.active)
              notify_others(p,cl,send_del_host);
           if(cl->socket)
             close(cl->socket);
	    p->status.active = 0;
	    p->status.remove = 1;
          }
      }
    
  cl->status.active = 0;
  
  if(cl->status.outgoing)
    {
      signal(SIGALRM, sigalrm_handler);
      seconds_till_retry = 5;
      alarm(seconds_till_retry);
      syslog(LOG_NOTICE, _("Trying to re-establish outgoing connection in 5 seconds"));
    }
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
      if(p->status.remove)
	continue;
      if(p->status.active && p->status.meta)
	{
          if(p->last_ping_time + timeout < now)
            {
              if(p->status.pinged && !p->status.got_pong)
                {
                  if(debug_lvl > 1)
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
int handle_new_meta_connection(conn_list_t *cl)
{
  conn_list_t *ncn;
  struct sockaddr client;
  int nfd, len = sizeof(client);
cp
  if((nfd = accept(cl->meta_socket, &client, &len)) < 0)
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

  ncn->status.meta = 1;
  ncn->next = conn_list;
  conn_list = ncn;
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
    handle_incoming_vpn_data(myself);

  if(FD_ISSET(myself->meta_socket, f))
    handle_new_meta_connection(myself);
cp
}

/*
  read, encrypt and send data that is
  available through the ethertap device
*/
void handle_tap_input(void)
{
  vpn_packet_t vp;
  ip_t from, to;
  int ether_type, lenin;
cp  
  memset(&vp, 0, sizeof(vp));
  if((lenin = read(tap_fd, &vp, MTU)) <= 0)
    {
      syslog(LOG_ERR, _("Error while reading from tapdevice: %m"));
      return;
    }

  total_tap_in += lenin;

  ether_type = ntohs(*((unsigned short*)(&vp.data[12])));
  if(ether_type != 0x0800)
    {
      if(debug_lvl > 3)
	syslog(LOG_INFO, _("Non-IP ethernet frame %04x from %02x:%02x:%02x:%02x:%02x:%02x"), ether_type, MAC_ADDR_V(vp.data[6]));
      return;
    }
  
  if(lenin < 32)
    {
      if(debug_lvl > 3)
	syslog(LOG_INFO, _("Dropping short packet from %02x:%02x:%02x:%02x:%02x:%02x"), MAC_ADDR_V(vp.data[6]));
      return;
    }

  from = ntohl(*((unsigned long*)(&vp.data[26])));
  to = ntohl(*((unsigned long*)(&vp.data[30])));

  vp.len = (length_t)lenin - 2;

  strip_mac_addresses(&vp);

  send_packet(to, &vp);
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
          sighup = 0;
	  if(debug_lvl > 1)
	    syslog(LOG_INFO, _("Rereading configuration file"));
          close_network_connections();
          clear_config();
          if(read_config_file(configfilename))
            {
              syslog(LOG_ERR, _("Unable to reread configuration file, exiting"));
              exit(0);
            }
          sleep(5);
          setup_network_connections();
          continue;
        }

      if(last_ping_check + timeout < time(NULL))
	/* Let's check if everybody is still alive */
	{
	  check_dead_connections();
          last_ping_check = time(NULL);
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
