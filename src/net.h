/*
    net.h -- header for net.c
    Copyright (C) 1998-2002 Ivo Timmermans <zarq@iname.com>
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

    $Id: net.h,v 1.9.4.49 2002/03/27 15:01:36 guus Exp $
*/

#ifndef __TINC_NET_H__
#define __TINC_NET_H__

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/time.h>

#include "config.h"

#ifdef ENABLE_JUMBOGRAMS
 #define MTU 9014        /* 9000 bytes payload + 14 bytes ethernet header */
 #define MAXSIZE 9100    /* MTU + header (seqno) and trailer (CBC padding and HMAC) */
 #define MAXBUFSIZE 9100 /* Must support TCP packets of length 9000. */
#else
 #define MTU 1514        /* 1500 bytes payload + 14 bytes ethernet header */
 #define MAXSIZE 1600    /* MTU + header (seqno) and trailer (CBC padding and HMAC) */
 #define MAXBUFSIZE 2100 /* Quite large but needed for support of keys up to 8192 bits. */
#endif

#define MAXSOCKETS 128 /* Overkill... */

#define MAXQUEUELENGTH 8 /* Maximum number of packats in a single queue */

typedef struct mac_t
{
  unsigned char x[6];
} mac_t;

typedef struct ipv4_t
{
  unsigned char x[4];
} ipv4_t;

typedef struct ip_mask_t {
  ipv4_t address;
  ipv4_t mask;
} ip_mask_t;

typedef struct ipv6_t
{
  unsigned short x[8];
} ipv6_t;

typedef unsigned short port_t;

typedef short length_t;

typedef union {
  struct sockaddr sa;
  struct sockaddr_in in;
  struct sockaddr_in6 in6;
} sockaddr_t;

#ifdef SA_LEN
#define SALEN(s) SA_LEN(&s)
#else
#define SALEN(s) (s.sa_family==AF_INET?sizeof(struct sockaddr_in):sizeof(struct sockaddr_in6))
#endif

typedef struct vpn_packet_t {
  length_t len;			/* the actual number of bytes in the `data' field */
  int priority;                 /* priority or TOS */
  unsigned int seqno;	        /* 32 bits sequence number (network byte order of course) */
  unsigned char data[MAXSIZE];
} vpn_packet_t;

typedef struct queue_element_t {
  void *packet;
  struct queue_element_t *prev;
  struct queue_element_t *next;
} queue_element_t;

typedef struct packet_queue_t {
  queue_element_t *head;
  queue_element_t *tail;
} packet_queue_t;

typedef struct outgoing_t {
  char *name;
  int timeout;
  struct config_t *cfg;
  struct addrinfo *ai;
  struct addrinfo *aip;
} outgoing_t;

typedef struct listen_socket_t {
  int tcp;
  int udp;
  sockaddr_t sa;
} listen_socket_t;

extern int maxtimeout;
extern int seconds_till_retry;
extern int addressfamily;

extern char *request_name[];
extern char *status_text[];

#include "connection.h"		/* Yes, very strange placement indeed, but otherwise the typedefs get all tangled up */

extern listen_socket_t listen_socket[MAXSOCKETS];
extern int listen_sockets;
extern int keyexpires;
extern int keylifetime;
extern int do_prune;
extern int do_purge;
extern char *myport;
extern time_t now;

extern void retry_outgoing(outgoing_t *);
extern void handle_incoming_vpn_data(int);
extern void finish_connecting(connection_t *);
extern void do_outgoing_connection(connection_t *);
extern int handle_new_meta_connection(int);
extern int setup_listen_socket(sockaddr_t *);
extern int setup_vpn_in_socket(sockaddr_t *);
extern void send_packet(struct node_t *, vpn_packet_t *);
extern void receive_packet(struct node_t *, vpn_packet_t *);
extern void receive_tcppacket(struct connection_t *, char *, int);
extern void broadcast_packet(struct node_t *, vpn_packet_t *);
extern int setup_network_connections(void);
extern void setup_outgoing_connection(struct outgoing_t *);
extern void try_outgoing_connections(void);
extern void close_network_connections(void);
extern void main_loop(void);
extern void terminate_connection(connection_t *, int);
extern void flush_queue(struct node_t *);
extern int read_rsa_public_key(struct connection_t *);

#endif /* __TINC_NET_H__ */
