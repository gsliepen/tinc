/*
    protocol_misc.c -- handle the meta-protocol, miscellaneous functions
    Copyright (C) 1999-2005 Ivo Timmermans,
                  2000-2006 Guus Sliepen <guus@tinc-vpn.org>

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

    $Id$
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

int maxoutbufsize = 0;

/* Status and error notification routines */

bool send_status(connection_t *c, int statusno, const char *statusstring)
{
	cp();

	if(!statusstring)
		statusstring = "Status";

	return send_request(c, "%d %d %s", STATUS, statusno, statusstring);
}

bool status_h(connection_t *c, char *request)
{
	int statusno;
	char statusstring[MAX_STRING_SIZE];

	cp();

	if(sscanf(request, "%*d %d " MAX_STRING, &statusno, statusstring) != 2) {
		logger(LOG_ERR, _("Got bad %s from %s (%s)"), "STATUS",
			   c->name, c->hostname);
		return false;
	}

	ifdebug(STATUS) logger(LOG_NOTICE, _("Status message from %s (%s): %d: %s"),
			   c->name, c->hostname, statusno, statusstring);

	return true;
}

bool send_error(connection_t *c, int err, const char *errstring)
{
	cp();

	if(!errstring)
		errstring = "Error";

	return send_request(c, "%d %d %s", ERROR, err, errstring);
}

bool error_h(connection_t *c, char *request)
{
	int err;
	char errorstring[MAX_STRING_SIZE];

	cp();

	if(sscanf(request, "%*d %d " MAX_STRING, &err, errorstring) != 2) {
		logger(LOG_ERR, _("Got bad %s from %s (%s)"), "ERROR",
			   c->name, c->hostname);
		return false;
	}

	ifdebug(ERROR) logger(LOG_NOTICE, _("Error message from %s (%s): %d: %s"),
			   c->name, c->hostname, err, errorstring);

	return false;
}

bool send_termreq(connection_t *c)
{
	cp();

	return send_request(c, "%d", TERMREQ);
}

bool termreq_h(connection_t *c, char *request)
{
	cp();

	return false;
}

bool send_ping(connection_t *c)
{
	cp();

	c->status.pinged = true;
	c->last_ping_time = time(NULL);

	return send_request(c, "%d", PING);
}

bool ping_h(connection_t *c, char *request)
{
	cp();

	return send_pong(c);
}

bool send_pong(connection_t *c)
{
	cp();

	return send_request(c, "%d", PONG);
}

bool pong_h(connection_t *c, char *request)
{
	cp();

	c->status.pinged = false;

	/* Succesful connection, reset timeout if this is an outgoing connection. */

	if(c->outgoing)
		c->outgoing->timeout = 0;

	return true;
}

/* Sending and receiving packets via TCP */

bool send_tcppacket(connection_t *c, vpn_packet_t *packet)
{
	cp();

	/* If there already is a lot of data in the outbuf buffer, discard this packet. */

	if(c->buffer->output->off > maxoutbufsize)
		return true;

	if(!send_request(c, "%d %hd", PACKET, packet->len))
		return false;

	return send_meta(c, (char *)packet->data, packet->len);
}

bool tcppacket_h(connection_t *c, char *request)
{
	short int len;

	cp();

	if(sscanf(request, "%*d %hd", &len) != 1) {
		logger(LOG_ERR, _("Got bad %s from %s (%s)"), "PACKET", c->name,
			   c->hostname);
		return false;
	}

	/* Set reqlen to len, this will tell receive_meta() that a tcppacket is coming. */

	c->tcplen = len;

	return true;
}
