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

    $Id: protocol.h,v 1.5.4.17 2000/11/22 19:55:53 guus Exp $
*/

#ifndef __TINC_PROTOCOL_H__
#define __TINC_PROTOCOL_H__

#include "net.h"
#include "subnet.h"

/* Protocol version. Different versions are incompatible,
   incompatible version have different protocols.
 */

#define PROT_CURRENT 8

/* Request numbers */

enum {
  ALL = -1,			     /* Guardian for allow_request */
  ID = 0, CHALLENGE, CHAL_REPLY, METAKEY, ACK,
  STATUS, ERROR, TERMREQ,
  PING,  PONG,
  ADD_HOST, DEL_HOST,
  ADD_SUBNET, DEL_SUBNET,
  KEY_CHANGED, REQ_KEY, ANS_KEY,
  LAST                               /* Guardian for the highest request number */
};

/* Maximum size of strings in a request */

#define MAX_STRING_SIZE 1024
#define MAX_STRING "%1024s"

extern int (*request_handlers[])(connection_t*);

extern int send_id(connection_t*);
extern int send_challenge(connection_t*);
extern int send_chal_reply(connection_t*);
extern int send_metakey(connection_t*);
extern int send_ack(connection_t*);
extern int send_status(connection_t*, int, char*);
extern int send_error(connection_t*, int, char*);
extern int send_termreq(connection_t*);
extern int send_ping(connection_t*);
extern int send_pong(connection_t*);
extern int send_add_host(connection_t*, connection_t*);
extern int send_del_host(connection_t*, connection_t*);
extern int send_add_subnet(connection_t*, subnet_t*);
extern int send_del_subnet(connection_t*, subnet_t*);
extern int send_key_changed(connection_t*, connection_t*);
extern int send_req_key(connection_t*, connection_t*);
extern int send_ans_key(connection_t*, connection_t*, char*);

/* Old functions */

extern int send_tcppacket(connection_t *, void *, int);
extern int notify_others(connection_t *, connection_t *, int (*function)(connection_t*, connection_t*));
extern int receive_request(connection_t *);
extern int check_id(char *);

#endif /* __TINC_PROTOCOL_H__ */
