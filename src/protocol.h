/*
    protocol.h -- header for protocol.c
    Copyright (C) 1999,2000 Ivo Timmermans <zarq@iname.com>

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

#ifndef __TINC_PROTOCOL_H__
#define __TINC_PROTOCOL_H__

#include "net.h"

enum {
  PROT_RESERVED = 0,                 /* reserved: do not use. */
  PROT_NOT_IN_USE,
  PROT_TOO_OLD = 2,
  PROT_3,
  PROT_4,
  PROT_ECHELON,
  PROT_6,
  PROT_CURRENT,                      /* protocol currently in use */
};

enum {
  ACK = 1,              /* acknowledged */
  AUTH_S_INIT = 10,     /* initiate authentication */
  AUTH_C_INIT,
  AUTH_S_SPP,           /* send passphrase */
  AUTH_C_SPP,
  AUTH_S_SKEY,          /* send g^k */
  AUTH_C_SKEY,
  AUTH_S_SACK,          /* send ack */
  AUTH_C_RACK,          /* waiting for ack */
  TERMREQ = 30,         /* terminate connection */
  PINGTIMEOUT,          /* terminate due to ping t.o. */
  DEL_HOST,		/* forward a termreq to others */
  PING = 40,            /* ping */
  PONG,
  ADD_HOST = 60,        /* Add new given host to connection list */
  BASIC_INFO,           /* some basic info follows */
  PASSPHRASE,           /* encrypted passphrase */
  PUBLIC_KEY,           /* public key in base-36 */
  HOLD = 80,            /* don't send any data */
  RESUME,               /* resume dataflow with new encryption key */
  CALCULATE = 100,      /* calculate the following numer^privkey and send me the result */  
  CALC_RES,             /* result of the above */
  ALMOST_KEY,           /* this number^privkey is the shared key */
  REQ_KEY = 160,        /* request public key */
  ANS_KEY,              /* answer to such request */
  KEY_CHANGED,		/* public key has changed */
};

extern int (*request_handlers[256])(conn_list_t*);

extern int send_ping(conn_list_t*);
extern int send_basic_info(conn_list_t *);
extern int send_termreq(conn_list_t *);
extern int send_timeout(conn_list_t *);
extern int send_key_request(ip_t);
extern void send_key_changed_all(void);

#endif /* __TINC_PROTOCOL_H__ */

