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

    $Id: net.h,v 1.9.4.38 2002/02/10 21:57:54 guus Exp $
*/

#ifndef __TINC_NET_H__
#define __TINC_NET_H__

#include <sys/time.h>

#include "config.h"

#define MTU 1514     /* 1500 bytes payload + 14 bytes ethernet header */
#define MAXSIZE 1600 /* MTU + header (seqno) and trailer (CBC padding and HMAC) */

#define MAXBUFSIZE 2048 /* Probably way too much, but it must fit every possible request. */

typedef struct mac_t
{
  unsigned char x[6];
} mac_t;

typedef unsigned long ipv4_t;

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

typedef struct vpn_packet_t {
  length_t len;			/* the actual number of bytes in the `data' field */
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
} outgoing_t;

extern int maxtimeout;
extern int seconds_till_retry;

extern char *request_name[];
extern char *status_text[];

#include "connection.h"		/* Yes, very strange placement indeed, but otherwise the typedefs get all tangled up */

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
