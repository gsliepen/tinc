/*
    protocol_misc.c -- handle the meta-protocol, miscellaneous functions
    Copyright (C) 1999-2002 Ivo Timmermans <itimmermans@bigfoot.com>,
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

    $Id: protocol_misc.c,v 1.1.4.3 2002/03/23 20:21:10 guus Exp $
*/

#include "config.h"

#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <stdio.h>
#include <stdarg.h>
#include <errno.h>

#include <utils.h>

#include "conf.h"
#include "net.h"
#include "netutl.h"
#include "protocol.h"
#include "meta.h"
#include "connection.h"

#include "system.h"

/* Status and error notification routines */

int send_status(connection_t *c, int statusno, char *statusstring)
{
cp
  if(!statusstring)
    statusstring = status_text[statusno];
cp
  return send_request(c, "%d %d %s", STATUS, statusno, statusstring);
}

int status_h(connection_t *c)
{
  int statusno;
  char statusstring[MAX_STRING_SIZE];
cp
  if(sscanf(c->buffer, "%*d %d "MAX_STRING, &statusno, statusstring) != 2)
    {
       syslog(LOG_ERR, _("Got bad %s from %s (%s)"), "STATUS",
              c->name, c->hostname);
       return -1;
    }

  if(debug_lvl >= DEBUG_STATUS)
    {
      syslog(LOG_NOTICE, _("Status message from %s (%s): %s: %s"),
             c->name, c->hostname, status_text[statusno], statusstring);
    }

cp
  return 0;
}

int send_error(connection_t *c, int err, char *errstring)
{
cp
  if(!errstring)
    errstring = strerror(err);
  return send_request(c, "%d %d %s", ERROR, err, errstring);
}

int error_h(connection_t *c)
{
  int err;
  char errorstring[MAX_STRING_SIZE];
cp
  if(sscanf(c->buffer, "%*d %d "MAX_STRING, &err, errorstring) != 2)
    {
       syslog(LOG_ERR, _("Got bad %s from %s (%s)"), "ERROR",
              c->name, c->hostname);
       return -1;
    }

  if(debug_lvl >= DEBUG_ERROR)
    {
      syslog(LOG_NOTICE, _("Error message from %s (%s): %s: %s"),
             c->name, c->hostname, strerror(err), errorstring);
    }

  terminate_connection(c, c->status.active);
cp
  return 0;
}

int send_termreq(connection_t *c)
{
cp
  return send_request(c, "%d", TERMREQ);
}

int termreq_h(connection_t *c)
{
cp
  terminate_connection(c, c->status.active);
cp
  return 0;
}

int send_ping(connection_t *c)
{
cp
  c->status.pinged = 1;
  c->last_ping_time = now;
cp
  return send_request(c, "%d", PING);
}

int ping_h(connection_t *c)
{
cp
  return send_pong(c);
}

int send_pong(connection_t *c)
{
cp
  return send_request(c, "%d", PONG);
}

int pong_h(connection_t *c)
{
cp
  c->status.pinged = 0;

  /* Succesful connection, reset timeout if this is an outgoing connection. */
  
  if(c->outgoing)
    c->outgoing->timeout = 0;
cp
  return 0;
}

/* Sending and receiving packets via TCP */

int send_tcppacket(connection_t *c, vpn_packet_t *packet)
{
  int x;
cp  
  /* Evil hack. */

  x = send_request(c, "%d %hd", PACKET, packet->len);

  if(x)
    return x;
cp
  return send_meta(c, packet->data, packet->len);
}

int tcppacket_h(connection_t *c)
{
  short int len;
cp  
  if(sscanf(c->buffer, "%*d %hd", &len) != 1)
    {
      syslog(LOG_ERR, _("Got bad %s from %s (%s)"), "PACKET", c->name, c->hostname);
      return -1;
    }

  /* Set reqlen to len, this will tell receive_meta() that a tcppacket is coming. */

  c->tcplen = len;
cp
  return 0;
}

/* Status strings */

char (*status_text[]) = {
  "Warning",
};

/* Error strings */

char (*error_text[]) = {
  "Error",
};
