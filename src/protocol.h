/*
    protocol.h -- header for protocol.c
    Copyright (C) 1999,2000 Ivo Timmermans <itimmermans@bigfoot.com>,
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

    $Id: protocol.h,v 1.6 2000/10/18 20:12:09 zarq Exp $
*/

#ifndef __TINC_PROTOCOL_H__
#define __TINC_PROTOCOL_H__

#include "net.h"
#include "subnet.h"

/* Protocol version. Different versions are incompatible,
   incompatible version have different protocols.
 */

#define PROT_CURRENT 8

/* Length of the challenge. Since the challenge will also
   contain the key for the symmetric cipher, it must be
   quite large.
 */

#define CHAL_LENGTH 1024 /* Okay, this is probably waaaaaaaaaaay too large */

/* Request numbers */

enum {
  ALL = -1,			     /* Guardian for allow_request */
  ID = 0, CHALLENGE, CHAL_REPLY, ACK,
  STATUS, ERROR, TERMREQ,
  PING,  PONG,
  ADD_HOST, DEL_HOST,
  ADD_SUBNET, DEL_SUBNET,
  KEY_CHANGED, REQ_KEY, ANS_KEY,
  LAST                               /* Guardian for the highest request number */
};

extern int (*request_handlers[])(conn_list_t*);

extern int send_id(conn_list_t*);
extern int send_challenge(conn_list_t*);
extern int send_chal_reply(conn_list_t*);
extern int send_ack(conn_list_t*);
extern int send_status(conn_list_t*, int, char*);
extern int send_error(conn_list_t*, int, char*);
extern int send_termreq(conn_list_t*);
extern int send_ping(conn_list_t*);
extern int send_pong(conn_list_t*);
extern int send_add_host(conn_list_t*, conn_list_t*);
extern int send_del_host(conn_list_t*, conn_list_t*);
extern int send_add_subnet(conn_list_t*, conn_list_t*, subnet_t*);
extern int send_del_subnet(conn_list_t*, conn_list_t*, subnet_t*);
extern int send_key_changed(conn_list_t*, conn_list_t*);
extern int send_req_key(conn_list_t*, conn_list_t*);
extern int send_ans_key(conn_list_t*, conn_list_t*, char*);

/* Old functions */

extern int send_tcppacket(conn_list_t *, void *, int);
extern int notify_others(conn_list_t *, conn_list_t *, int (*function)(conn_list_t*, conn_list_t*));

#endif /* __TINC_PROTOCOL_H__ */
