/*
    protocol_misc.c -- handle the meta-protocol, miscellaneous functions
    Copyright (C) 1999-2003 Ivo Timmermans <ivo@o2w.nl>,
                  2000-2003 Guus Sliepen <guus@sliepen.eu.org>

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

    $Id: protocol_misc.c,v 1.1.4.11 2003/07/17 15:06:26 guus Exp $
*/

#include "system.h"

#include "conf.h"
#include "connection.h"
#include "logger.h"
#include "meta.h"
#include "net.h"
#include "netutl.h"
#include "protocol.h"
#include "utils.h"

/* Status and error notification routines */

int send_status(connection_t *c, int statusno, char *statusstring)
{
	cp();

	if(!statusstring)
		statusstring = "Status";

	return send_request(c, "%d %d %s", STATUS, statusno, statusstring);
}

int status_h(connection_t *c)
{
	int statusno;
	char statusstring[MAX_STRING_SIZE];

	cp();

	if(sscanf(c->buffer, "%*d %d " MAX_STRING, &statusno, statusstring) != 2) {
		logger(LOG_ERR, _("Got bad %s from %s (%s)"), "STATUS",
			   c->name, c->hostname);
		return -1;
	}

	ifdebug(STATUS) logger(LOG_NOTICE, _("Status message from %s (%s): %d: %s"),
			   c->name, c->hostname, statusno, statusstring);

	return 0;
}

int send_error(connection_t *c, int err, char *errstring)
{
	cp();

	if(!errstring)
		errstring = "Error";

	return send_request(c, "%d %d %s", ERROR, err, errstring);
}

int error_h(connection_t *c)
{
	int err;
	char errorstring[MAX_STRING_SIZE];

	cp();

	if(sscanf(c->buffer, "%*d %d " MAX_STRING, &err, errorstring) != 2) {
		logger(LOG_ERR, _("Got bad %s from %s (%s)"), "ERROR",
			   c->name, c->hostname);
		return -1;
	}

	ifdebug(ERROR) logger(LOG_NOTICE, _("Error message from %s (%s): %d: %s"),
			   c->name, c->hostname, err, errorstring);

	terminate_connection(c, c->status.active);

	return 0;
}

int send_termreq(connection_t *c)
{
	cp();

	return send_request(c, "%d", TERMREQ);
}

int termreq_h(connection_t *c)
{
	cp();

	terminate_connection(c, c->status.active);

	return 0;
}

int send_ping(connection_t *c)
{
	cp();

	c->status.pinged = 1;
	c->last_ping_time = now;

	return send_request(c, "%d", PING);
}

int ping_h(connection_t *c)
{
	cp();

	return send_pong(c);
}

int send_pong(connection_t *c)
{
	cp();

	return send_request(c, "%d", PONG);
}

int pong_h(connection_t *c)
{
	cp();

	c->status.pinged = 0;

	/* Succesful connection, reset timeout if this is an outgoing connection. */

	if(c->outgoing)
		c->outgoing->timeout = 0;

	return 0;
}

/* Sending and receiving packets via TCP */

int send_tcppacket(connection_t *c, vpn_packet_t *packet)
{
	int x;

	cp();

	/* Evil hack. */

	x = send_request(c, "%d %hd", PACKET, packet->len);

	if(x)
		return x;

	return send_meta(c, packet->data, packet->len);
}

int tcppacket_h(connection_t *c)
{
	short int len;

	cp();

	if(sscanf(c->buffer, "%*d %hd", &len) != 1) {
		logger(LOG_ERR, _("Got bad %s from %s (%s)"), "PACKET", c->name,
			   c->hostname);
		return -1;
	}

	/* Set reqlen to len, this will tell receive_meta() that a tcppacket is coming. */

	c->tcplen = len;

	return 0;
}
