/*
    protocol.h -- header for protocol.c
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

    $Id: protocol.h,v 1.5.4.29 2002/03/22 11:43:48 guus Exp $
*/

#ifndef __TINC_PROTOCOL_H__
#define __TINC_PROTOCOL_H__

#include "net.h"
#include "node.h"
#include "subnet.h"

/* Protocol version. Different versions are incompatible,
   incompatible version have different protocols.
 */

#define PROT_CURRENT 14

/* Request numbers */

enum {
  ALL = -1,			     /* Guardian for allow_request */
  ID = 0, METAKEY, CHALLENGE, CHAL_REPLY, ACK,
  STATUS, ERROR, TERMREQ,
  PING, PONG,
//  ADD_NODE, DEL_NODE,
  ADD_SUBNET, DEL_SUBNET,
  ADD_EDGE, DEL_EDGE,
  KEY_CHANGED, REQ_KEY, ANS_KEY,
  PACKET,
  LAST                               /* Guardian for the highest request number */
};

typedef struct past_request_t {
  char *request;
  time_t firstseen;
} past_request_t;

/* Maximum size of strings in a request */

#define MAX_STRING_SIZE 2048
#define MAX_STRING "%2048s"

/* Basic functions */

extern int send_request(connection_t*, const char*, ...);
extern int receive_request(connection_t *);
extern int check_id(char *);

extern void init_requests(void);
extern void exit_requests(void);
extern int seen_request(char *);
extern void age_past_requests(void);

/* Requests */

extern int send_id(connection_t *);
extern int send_metakey(connection_t *);
extern int send_challenge(connection_t *);
extern int send_chal_reply(connection_t *);
extern int send_ack(connection_t *);
extern int send_status(connection_t *, int, char *);
extern int send_error(connection_t *, int, char *);
extern int send_termreq(connection_t *);
extern int send_ping(connection_t *);
extern int send_pong(connection_t *);
// extern int send_add_node(connection_t *, node_t *);
// extern int send_del_node(connection_t *, node_t *);
extern int send_add_subnet(connection_t *, subnet_t *);
extern int send_del_subnet(connection_t *, subnet_t *);
extern int send_add_edge(connection_t *, edge_t *);
extern int send_del_edge(connection_t *, edge_t *);
extern int send_key_changed(connection_t *, node_t *);
extern int send_req_key(connection_t *, node_t *, node_t *);
extern int send_ans_key(connection_t *, node_t *, node_t *);
extern int send_tcppacket(connection_t *, vpn_packet_t *);

/* Request handlers  */

extern int (*request_handlers[])(connection_t *);

extern int id_h(connection_t *);
extern int metakey_h(connection_t *);
extern int challenge_h(connection_t *);
extern int chal_reply_h(connection_t *);
extern int ack_h(connection_t *);
extern int status_h(connection_t *);
extern int error_h(connection_t *);
extern int termreq_h(connection_t *);
extern int ping_h(connection_t *);
extern int pong_h(connection_t *);
// extern int add_node_h(connection_t *);
// extern int del_node_h(connection_t *);
extern int add_subnet_h(connection_t *);
extern int del_subnet_h(connection_t *);
extern int add_edge_h(connection_t *);
extern int del_edge_h(connection_t *);
extern int key_changed_h(connection_t *);
extern int req_key_h(connection_t *);
extern int ans_key_h(connection_t *);
extern int tcppacket_h(connection_t *);

#endif /* __TINC_PROTOCOL_H__ */
