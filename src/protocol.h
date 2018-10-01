#ifndef TINC_PROTOCOL_H
#define TINC_PROTOCOL_H

/*
    protocol.h -- header for protocol.c
    Copyright (C) 1999-2005 Ivo Timmermans,
                  2000-2015 Guus Sliepen <guus@tinc-vpn.org>

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/

/* Protocol version. Different versions are incompatible,
   incompatible version have different protocols.
 */

#define PROT_CURRENT 17

/* Silly Windows */

#ifdef ERROR
#undef ERROR
#endif

/* Request numbers */

typedef enum request_t {
	PROXY = -2,
	ALL = -1,                                       /* Guardian for allow_request */
	ID = 0, METAKEY, CHALLENGE, CHAL_REPLY, ACK,
	STATUS, ERROR, TERMREQ,
	PING, PONG,
	ADD_SUBNET, DEL_SUBNET,
	ADD_EDGE, DEL_EDGE,
	KEY_CHANGED, REQ_KEY, ANS_KEY,
	PACKET,
	LAST                                            /* Guardian for the highest request number */
} request_t;

typedef struct past_request_t {
	char *request;
	time_t firstseen;
} past_request_t;

extern bool tunnelserver;
extern bool strictsubnets;

/* Maximum size of strings in a request.
 * scanf terminates %2048s with a NUL character,
 * but the NUL character can be written after the 2048th non-NUL character.
 */

#define MAX_STRING_SIZE 2049
#define MAX_STRING "%2048s"

#include "edge.h"
#include "net.h"
#include "node.h"
#include "subnet.h"

/* Basic functions */

extern bool send_request(struct connection_t *c, const char *format, ...) __attribute__((__format__(printf, 2, 3)));
extern void forward_request(struct connection_t *c);
extern bool receive_request(struct connection_t *c);
extern bool check_id(const char *name);

extern void init_requests(void);
extern void exit_requests(void);
extern bool seen_request(char *request);
extern void age_past_requests(void);

/* Requests */

extern bool send_id(struct connection_t *c);
extern bool send_metakey(struct connection_t *c);
extern bool send_challenge(struct connection_t *c);
extern bool send_chal_reply(struct connection_t *c);
extern bool send_ack(struct connection_t *c);
extern bool send_ping(struct connection_t *c);
extern bool send_pong(struct connection_t *c);
extern bool send_add_subnet(struct connection_t *c, const struct subnet_t *subnet);
extern bool send_del_subnet(struct connection_t *c, const struct subnet_t *subnet);
extern bool send_add_edge(struct connection_t *c, const struct edge_t *e);
extern bool send_del_edge(struct connection_t *c, const struct edge_t *e);
extern void send_key_changed(void);
extern bool send_req_key(struct node_t *n);
extern bool send_ans_key(struct node_t *n);
extern bool send_tcppacket(struct connection_t *c, const struct vpn_packet_t *packet);

/* Request handlers  */

extern bool id_h(struct connection_t *c);
extern bool metakey_h(struct connection_t *c);
extern bool challenge_h(struct connection_t *c);
extern bool chal_reply_h(struct connection_t *c);
extern bool ack_h(struct connection_t *c);
extern bool ping_h(struct connection_t *c);
extern bool pong_h(struct connection_t *c);
extern bool add_subnet_h(struct connection_t *c);
extern bool del_subnet_h(struct connection_t *c);
extern bool add_edge_h(struct connection_t *c);
extern bool del_edge_h(struct connection_t *c);
extern bool key_changed_h(struct connection_t *c);
extern bool req_key_h(struct connection_t *c);
extern bool ans_key_h(struct connection_t *c);
extern bool tcppacket_h(struct connection_t *c);

#endif
