/*
    net.c -- most of the network code
    Copyright (C) 1998,99 Ivo Timmermans <zarq@iname.com>

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

int tap_fd = -1;

int total_tap_in = 0;
int total_tap_out = 0;
int total_socket_in = 0;
int total_socket_out = 0;

time_t last_ping_time = 0;

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
  int r;
  real_packet_t rp;
cp
  do_encrypt((vpn_packet_t*)packet, &rp, cl->key);
  rp.from = myself->vpn_ip;

  if(debug_lvl > 3)
    syslog(LOG_ERR, "Sent %d bytes to %lx", rp.len, cl->vpn_ip);

  if((r = send(cl->socket, (char*)&rp, rp.len, 0)) < 0)
    {
      syslog(LOG_ERR, "Error sending data: %m");
      return -1;
    }

  total_socket_out += r;
cp
  return 0;
}

int xrecv(conn_list_t *cl, void *packet)
{
  vpn_packet_t vp;
  int lenin;
cp
  do_decrypt((real_packet_t*)packet, &vp, cl->key);
  add_mac_addresses(&vp);

  if((lenin = write(tap_fd, &vp, vp.len + sizeof(vp.len))) < 0)
    syslog(LOG_ERR, "Can't write to tap device: %m");
  else
    total_tap_out += lenin;
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
  if(debug_lvl > 3)
    syslog(LOG_DEBUG, "packet to queue: %d", s);

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
    syslog(LOG_DEBUG, "queue flushed");
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
      if(debug_lvl > 1)
	syslog(LOG_DEBUG, "Flushing send queue for " IP_ADDR_S,
	       IP_ADDR_V(cl->vpn_ip));
      flush_queue(cl, &(cl->sq), xsend);
    }

  if(cl->rq)
    {
      if(debug_lvl > 1)
	syslog(LOG_DEBUG, "Flushing receive queue for " IP_ADDR_S,
	       IP_ADDR_V(cl->vpn_ip));
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
      if(debug_lvl > 2)
        {
          syslog(LOG_NOTICE, "trying to look up " IP_ADDR_S " in connection list failed.",
	         IP_ADDR_V(to));
        }
      for(cl = conn_list; cl != NULL && !cl->status.outgoing; cl = cl->next);
      if(!cl)
        { /* No open outgoing connection has been found. */
	  if(debug_lvl > 2)
	    syslog(LOG_NOTICE, "There is no remote host I can send this packet to.");
          return -1;
        }
    }

  if(my_key_expiry <= time(NULL))
    regenerate_keys();

  if(!cl->status.dataopen)
    if(setup_vpn_connection(cl) < 0)
      return -1;

  if(!cl->status.validkey)
    {
      add_queue(&(cl->sq), packet, packet->len + 2);
      if(!cl->status.waitingforkey)
	send_key_request(cl->vpn_ip);			/* Keys should be sent to the host running the tincd */
      return 0;
    }

  if(!cl->status.active)
    {
      add_queue(&(cl->sq), packet, packet->len + 2);
      if(debug_lvl > 1)
	syslog(LOG_INFO, IP_ADDR_S " is not ready, queueing packet.", IP_ADDR_V(cl->vpn_ip));
      return 0; /* We don't want to mess up, do we? */
    }

  /* can we send it? can we? can we? huh? */
cp
  return xsend(cl, packet);
}

int send_broadcast(conn_list_t *cl, vpn_packet_t *packet)
{
  conn_list_t *p;
cp
  for(p = cl; p != NULL; p = p->next)
    if(send_packet(p->real_ip, packet) < 0)
      {
	syslog(LOG_ERR, "Could not send a broadcast packet to %08lx (%08lx): %m",
	       p->vpn_ip, p->real_ip);
	break; /* FIXME: should retry later, and send a ping over the metaconnection. */
      }
cp
  return 0;
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
      syslog(LOG_ERR, "Could not open %s: %m", tapfname);
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
cp
  if((nfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0)
    {
      syslog(LOG_ERR, "Creating metasocket failed: %m");
      return -1;
    }

  if(setsockopt(nfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)))
    {
      syslog(LOG_ERR, "setsockopt: %m");
      return -1;
    }

  flags = fcntl(nfd, F_GETFL);
  if(fcntl(nfd, F_SETFL, flags | O_NONBLOCK) < 0)
    {
      syslog(LOG_ERR, "fcntl: %m");
      return -1;
    }

  memset(&a, 0, sizeof(a));
  a.sin_family = AF_INET;
  a.sin_port = htons(port);
  a.sin_addr.s_addr = htonl(INADDR_ANY);

  if(bind(nfd, (struct sockaddr *)&a, sizeof(struct sockaddr)))
    {
      syslog(LOG_ERR, "Can't bind to port %hd/tcp: %m", port);
      return -1;
    }

  if(listen(nfd, 3))
    {
      syslog(LOG_ERR, "listen: %m");
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
      syslog(LOG_ERR, "Creating socket failed: %m");
      return -1;
    }

  if(setsockopt(nfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)))
    {
      syslog(LOG_ERR, "setsockopt: %m");
      return -1;
    }

  flags = fcntl(nfd, F_GETFL);
  if(fcntl(nfd, F_SETFL, flags | O_NONBLOCK) < 0)
    {
      syslog(LOG_ERR, "fcntl: %m");
      return -1;
    }

  memset(&a, 0, sizeof(a));
  a.sin_family = AF_INET;
  a.sin_port = htons(port);
  a.sin_addr.s_addr = htonl(INADDR_ANY);

  if(bind(nfd, (struct sockaddr *)&a, sizeof(struct sockaddr)))
    {
      syslog(LOG_ERR, "Can't bind to port %hd/udp: %m", port);
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
  if((cfg = get_config_val(upstreamport)) == NULL)
    cl->port = 655;
  else
    cl->port = cfg->data.val;

  cl->meta_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if(cl->meta_socket == -1)
    {
      syslog(LOG_ERR, "Creating socket failed: %m");
      return -1;
    }

  a.sin_family = AF_INET;
  a.sin_port = htons(cl->port);
  a.sin_addr.s_addr = htonl(cl->real_ip);

  if(connect(cl->meta_socket, (struct sockaddr *)&a, sizeof(a)) == -1)
    {
      syslog(LOG_ERR, IP_ADDR_S ":%d: %m", IP_ADDR_V(cl->real_ip), cl->port);
      return -1;
    }

  flags = fcntl(cl->meta_socket, F_GETFL);
  if(fcntl(cl->meta_socket, F_SETFL, flags | O_NONBLOCK) < 0)
    {
      syslog(LOG_ERR, "fcntl: %m");
      return -1;
    }

  cl->hostname = hostlookup(htonl(cl->real_ip));

  syslog(LOG_INFO, "Connected to %s:%hd" , cl->hostname, cl->port);
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
int setup_outgoing_connection(ip_t ip)
{
  conn_list_t *ncn;
cp
  ncn = new_conn_list();
  ncn->real_ip = ip;

  if(setup_outgoing_meta_socket(ncn) < 0)
    {
      syslog(LOG_ERR, "Could not set up a meta connection.");
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
      syslog(LOG_ERR, "No value for my VPN IP given");
      return -1;
    }

  myself->vpn_ip = cfg->data.ip->ip;
  myself->vpn_mask = cfg->data.ip->mask;

  if(!(cfg = get_config_val(listenport)))
    myself->port = 655;
  else
    myself->port = cfg->data.val;

  if((myself->meta_socket = setup_listen_meta_socket(myself->port)) < 0)
    {
      syslog(LOG_ERR, "Unable to set up a listening socket");
      return -1;
    }

  if((myself->socket = setup_vpn_in_socket(myself->port)) < 0)
    {
      syslog(LOG_ERR, "Unable to set up an incoming vpn data socket");
      close(myself->meta_socket);
      return -1;
    }

  myself->status.active = 1;

  syslog(LOG_NOTICE, "Ready: listening on port %d.", myself->port);
cp
  return 0;
}

/*
  setup all initial network connections
*/
int setup_network_connections(void)
{
  config_t const *cfg;
cp
  if((cfg = get_config_val(pingtimeout)) == NULL)
    timeout = 10;
  else
    timeout = cfg->data.val;

  if(setup_tap_fd() < 0)
    return -1;

  if(setup_myself() < 0)
    return -1;

  if((cfg = get_config_val(upstreamip)) == NULL)
    /* No upstream IP given, we're listen only. */
    return 0;

  if(setup_outgoing_connection(cfg->data.ip->ip))
    return -1;
cp
  return 0;
}

RETSIGTYPE
sigalrm_handler(int a)
{
  config_t const *cfg;
  static int seconds_till_retry;
cp
  cfg = get_config_val(upstreamip);

  if(!setup_outgoing_connection(cfg->data.ip->ip))
    {
      signal(SIGALRM, SIG_IGN);
      seconds_till_retry = 5;
    }
  else
    {
      signal(SIGALRM, sigalrm_handler);
      seconds_till_retry += 5;
      alarm(seconds_till_retry);
      syslog(LOG_ERR, "Still failed to connect to other. Will retry in %d seconds.",
	     seconds_till_retry);
    }
cp
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

  syslog(LOG_NOTICE, "Terminating.");
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
  if(debug_lvl > 1)
    syslog(LOG_DEBUG, "Opening UDP socket to " IP_ADDR_S, IP_ADDR_V(cl->real_ip));

  nfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if(nfd == -1)
    {
      syslog(LOG_ERR, "Creating data socket failed: %m");
      return -1;
    }

  a.sin_family = AF_INET;
  a.sin_port = htons(cl->port);
  a.sin_addr.s_addr = htonl(cl->real_ip);

  if(connect(nfd, (struct sockaddr *)&a, sizeof(a)) == -1)
    {
      syslog(LOG_ERR, "Create connection to %08lx:%d failed: %m", ntohs(cl->real_ip),
	     cl->port);
      return -1;
    }

  flags = fcntl(nfd, F_GETFL);
  if(fcntl(nfd, F_SETFL, flags | O_NONBLOCK) < 0)
    {
      syslog(LOG_ERR, "This is a bug: %s:%d: %d:%m", __FILE__, __LINE__, nfd);
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
      syslog(LOG_ERR, "Error: getpeername: %m");
      return NULL;
    }

  p->hostname = hostlookup(ci.sin_addr.s_addr);
  p->real_ip = ntohl(ci.sin_addr.s_addr);
  p->meta_socket = sfd;
  p->status.meta = 1;
  p->buflen = 0;
  
  syslog(LOG_NOTICE, "Connection from %s:%d", p->hostname, htons(ci.sin_port));

  if(send_basic_info(p) < 0)
    {
      free(p);
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
      syslog(LOG_ERR, "This is a bug: %s:%d: %d:%m", __FILE__, __LINE__, cl->socket);
      return -1;
    }
  if(x)
    {
      syslog(LOG_ERR, "Incoming data socket error: %s", sys_errlist[x]);
      return -1;
    }

  rp.len = -1;
  lenin = recvfrom(cl->socket, &rp, MTU, 0, NULL, NULL);
  if(lenin <= 0)
    {
      syslog(LOG_ERR, "Receiving data failed: %m");
      return -1;
    }
  total_socket_in += lenin;
  if(rp.len >= 0)
    {
      f = lookup_conn(rp.from);
      if(debug_lvl > 3)
	syslog(LOG_DEBUG, "packet from " IP_ADDR_S " (len %d)",
	       IP_ADDR_V(rp.from), rp.len);
      if(!f)
	{
	  syslog(LOG_ERR, "Got packet from unknown source " IP_ADDR_S,
		 IP_ADDR_V(rp.from));
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
cp
  if(cl->status.remove)
    return;

  if(debug_lvl > 0)
    syslog(LOG_NOTICE, "Closing connection with %s.", cl->hostname);

  if(cl->status.timeout)
    send_timeout(cl);
  else if(!cl->status.termreq)
    send_termreq(cl);

  close(cl->socket);
  if(cl->status.meta)
    close(cl->meta_socket);

  if(cl->status.outgoing)
    {
      alarm(5);
      signal(SIGALRM, sigalrm_handler);
      syslog(LOG_NOTICE, "Try to re-establish outgoing connection in 5 seconds.");
    }
  
  cl->status.remove = 1;
cp
}

/*
  send out a ping request to all active
  connections
*/
int send_broadcast_ping(void)
{
  conn_list_t *p;
cp
  for(p = conn_list; p != NULL; p = p->next)
    {
      if(p->status.remove)
	continue;
      if(p->status.active && p->status.meta)
	{
	  if(send_ping(p))
	    terminate_connection(p);
	  else
	    {
	      p->status.pinged = 1;
	      p->status.got_pong = 0;
	    }
	}
    }

  last_ping_time = time(NULL);
cp
  return 0;
}

/*
  end all connections that did not respond
  to the ping probe in time
*/
int check_dead_connections(void)
{
  conn_list_t *p;
cp
  for(p = conn_list; p != NULL; p = p->next)
    {
      if(p->status.remove)
	continue;
      if(p->status.active && p->status.meta && p->status.pinged && !p->status.got_pong)
	{
	  syslog(LOG_INFO, "%s (" IP_ADDR_S ") didn't respond to ping",
		 p->hostname, IP_ADDR_V(p->vpn_ip));
	  p->status.timeout = 1;
	  terminate_connection(p);
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
      syslog(LOG_ERR, "Accepting a new connection failed: %m");
      return -1;
    }

  if((ncn = create_new_connection(nfd)) == NULL)
    {
      shutdown(nfd, 2);
      close(nfd);
      syslog(LOG_NOTICE, "Closed attempted connection.");
      return 0;
    }

  ncn->status.meta = 1;
  ncn->next = conn_list;
  conn_list = ncn;
cp
  return 0;
}

/*
  dispatch any incoming meta requests
*/
int handle_incoming_meta_data(conn_list_t *cl)
{
  int x, l = sizeof(x);
  int request, oldlen, p, i;
  int lenin = 0;
cp
  if(getsockopt(cl->meta_socket, SOL_SOCKET, SO_ERROR, &x, &l) < 0)
    {
      syslog(LOG_ERR, "This is a bug: %s:%d: %d:%m", __FILE__, __LINE__, cl->meta_socket);
      return -1;
    }
  if(x)
    {
      syslog(LOG_ERR, "Metadata socket error: %s", sys_errlist[x]);
      return -1;
    }

  if(cl->buflen >= MAXBUFSIZE)
    {
      syslog(LOG_ERR, "Metadata read buffer full! Discarding contents.");
      cl->buflen = 0;
    }

  lenin = read(cl->meta_socket, cl->buffer, MAXBUFSIZE-cl->buflen);

  if(lenin<=0)
    {
      syslog(LOG_ERR, "Metadata socket read error: %m");
      return -1;
    }

  oldlen = cl->buflen;
  cl->buflen += lenin;

  for(;;)
    {
      p=0;

      for(i = oldlen; i < cl->buflen; i++)
        {
          if(cl->buffer[i] == '\n')
            {
              p = i + 1;
              cl->buffer[p] = 0;  /* add end-of-string so we can use sscanf */
              break;
            }
        }

      if(p)
        {
          if(sscanf(cl->buffer, "%d", &request) == 1)
            {
              if(request_handlers[request] == NULL)
                {
                  syslog(LOG_ERR, "Unknown request: %s", cl->buffer);
                  return 0;
                }

              if(debug_lvl > 3)
                syslog(LOG_DEBUG, "Got request: %s", cl->buffer);                             

              request_handlers[request](cl);
            }
          else
            {
              syslog(LOG_ERR, "Bogus data received: %s", cl->buffer);
            }

          cl->buflen -= p;
          memmove(cl->buffer, cl->buffer + p, cl->buflen);
          oldlen = 0;
        }
      else
        {
          break;
        }
    }
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
	    syslog(LOG_ERR, "Outgoing data socket error: %s", sys_errlist[x]);
	    terminate_connection(p);
	    return;
	  }  

      if(p->status.meta)
	if(FD_ISSET(p->meta_socket, f))
	  if(handle_incoming_meta_data(p) < 0)
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
      syslog(LOG_ERR, "Error while reading from tapdevice: %m");
      return;
    }

  total_tap_in += lenin;

  ether_type = ntohs(*((unsigned short*)(&vp.data[12])));
  if(ether_type != 0x0800)
    {
      if(debug_lvl > 0)
	syslog(LOG_INFO, "Non-IP ethernet frame %04x from " MAC_ADDR_S,
	       ether_type, MAC_ADDR_V(vp.data[6]));
      return;
    }
  
  if(lenin < 32)
    {
      if(debug_lvl > 0)
	syslog(LOG_INFO, "Dropping short packet");
      return;
    }

  from = ntohl(*((unsigned long*)(&vp.data[26])));
  to = ntohl(*((unsigned long*)(&vp.data[30])));

  if(debug_lvl > 3)
    syslog(LOG_DEBUG, "An IP packet (%04x) for " IP_ADDR_S " from " IP_ADDR_S,
	   ether_type, IP_ADDR_V(to), IP_ADDR_V(from));
  if(debug_lvl > 4)
    syslog(LOG_DEBUG, MAC_ADDR_S " to " MAC_ADDR_S,
	   MAC_ADDR_V(vp.data[0]), MAC_ADDR_V(vp.data[6]));
  
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
cp
  last_ping_time = time(NULL);

  for(;;)
    {
      tv.tv_sec = timeout;
      tv.tv_usec = 0;

      prune_conn_list();
      build_fdset(&fset);

      if((r = select(FD_SETSIZE, &fset, NULL, NULL, &tv)) < 0)
        {
	  if(errno == EINTR) /* because of alarm */
	    continue;
          syslog(LOG_ERR, "Error while waiting for input: %m");
          return;
        }

      if(r == 0 || last_ping_time + timeout < time(NULL))
	/* Timeout... hm... something might be wrong. */
	{
	  check_dead_connections();
	  send_broadcast_ping();
	  continue;
	}

      check_network_activity(&fset);

      /* local tap data */
      if(FD_ISSET(tap_fd, &fset))
	handle_tap_input();
    }
cp
}
