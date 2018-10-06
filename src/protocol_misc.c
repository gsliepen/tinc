/*
    protocol_misc.c -- handle the meta-protocol, miscellaneous functions
    Copyright (C) 1999-2005 Ivo Timmermans,
                  2000-2013 Guus Sliepen <guus@tinc-vpn.org>

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

#include "system.h"

#include "address_cache.h"
#include "conf.h"
#include "connection.h"
#include "logger.h"
#include "meta.h"
#include "net.h"
#include "netutl.h"
#include "protocol.h"
#include "utils.h"
#include "xalloc.h"

#ifndef MIN
#define MIN(x, y) (((x)<(y))?(x):(y))
#endif

int maxoutbufsize = 0;
int mtu_info_interval = 5;
int udp_info_interval = 5;

bool send_termreq(connection_t *c) {
	return send_request(c, "%d", TERMREQ);
}

bool termreq_h(connection_t *c, const char *request) {
	(void)c;
	(void)request;
	return false;
}

bool send_ping(connection_t *c) {
	c->status.pinged = true;
	c->last_ping_time = now.tv_sec;

	return send_request(c, "%d", PING);
}

bool ping_h(connection_t *c, const char *request) {
	(void)request;
	return send_pong(c);
}

bool send_pong(connection_t *c) {
	return send_request(c, "%d", PONG);
}

bool pong_h(connection_t *c, const char *request) {
	(void)request;
	c->status.pinged = false;

	/* Successful connection, reset timeout if this is an outgoing connection. */

	if(c->outgoing) {
		c->outgoing->timeout = 0;
		reset_address_cache(c->outgoing->address_cache, &c->address);
	}

	return true;
}

/* Sending and receiving packets via TCP */

bool send_tcppacket(connection_t *c, const vpn_packet_t *packet) {
	/* If there already is a lot of data in the outbuf buffer, discard this packet.
	   We use a very simple Random Early Drop algorithm. */

	if(2.0 * c->outbuf.len / (float)maxoutbufsize - 1 > (float)rand() / (float)RAND_MAX) {
		return true;
	}

	if(!send_request(c, "%d %d", PACKET, packet->len)) {
		return false;
	}

	return send_meta(c, (char *)DATA(packet), packet->len);
}

bool tcppacket_h(connection_t *c, const char *request) {
	short int len;

	if(sscanf(request, "%*d %hd", &len) != 1) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Got bad %s from %s (%s)", "PACKET", c->name,
		       c->hostname);
		return false;
	}

	/* Set reqlen to len, this will tell receive_meta() that a tcppacket is coming. */

	c->tcplen = len;

	return true;
}

bool send_sptps_tcppacket(connection_t *c, const char *packet, int len) {
	/* If there already is a lot of data in the outbuf buffer, discard this packet.
	   We use a very simple Random Early Drop algorithm. */

	if(2.0 * c->outbuf.len / (float)maxoutbufsize - 1 > (float)rand() / (float)RAND_MAX) {
		return true;
	}

	if(!send_request(c, "%d %d", SPTPS_PACKET, len)) {
		return false;
	}

	send_meta_raw(c, packet, len);
	return true;
}

bool sptps_tcppacket_h(connection_t *c, const char *request) {
	short int len;

	if(sscanf(request, "%*d %hd", &len) != 1) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Got bad %s from %s (%s)", "SPTPS_PACKET", c->name,
		       c->hostname);
		return false;
	}

	/* Set sptpslen to len, this will tell receive_meta() that a SPTPS packet is coming. */

	c->sptpslen = len;

	return true;
}

/* Transmitting UDP information */

bool send_udp_info(node_t *from, node_t *to) {
	/* If there's a static relay in the path, there's no point in sending the message
	   farther than the static relay. */
	to = (to->via == myself) ? to->nexthop : to->via;

	if(to == NULL) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Something went wrong when selecting relay - possible fake UDP_INFO");
		return false;
	}

	/* Skip cases where sending UDP info messages doesn't make sense.
	   This is done here in order to avoid repeating the same logic in multiple callsites. */

	if(to == myself) {
		return true;
	}

	if(!to->status.reachable) {
		return true;
	}

	if(from == myself) {
		if(to->connection) {
			return true;
		}

		struct timeval elapsed;

		timersub(&now, &to->udp_info_sent, &elapsed);

		if(elapsed.tv_sec < udp_info_interval) {
			return true;
		}
	}

	if((myself->options | from->options | to->options) & OPTION_TCPONLY) {
		return true;
	}

	if((to->nexthop->options >> 24) < 5) {
		return true;
	}

	char *from_address, *from_port;
	/* If we're the originator, the address we use is irrelevant
	   because the first intermediate node will ignore it.
	   We use our local address as it somewhat makes sense
	   and it's simpler than introducing an encoding for "null" addresses anyway. */
	sockaddr2str((from != myself) ? &from->address : &to->nexthop->connection->edge->local_address, &from_address, &from_port);

	bool x = send_request(to->nexthop->connection, "%d %s %s %s %s", UDP_INFO, from->name, to->name, from_address, from_port);

	free(from_address);
	free(from_port);

	if(from == myself) {
		to->udp_info_sent = now;
	}

	return x;
}

bool udp_info_h(connection_t *c, const char *request) {
	char from_name[MAX_STRING_SIZE];
	char to_name[MAX_STRING_SIZE];
	char from_address[MAX_STRING_SIZE];
	char from_port[MAX_STRING_SIZE];

	if(sscanf(request, "%*d "MAX_STRING" "MAX_STRING" "MAX_STRING" "MAX_STRING, from_name, to_name, from_address, from_port) != 4) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Got bad %s from %s (%s)", "UDP_INFO", c->name, c->hostname);
		return false;
	}

	if(!check_id(from_name) || !check_id(to_name)) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Got bad %s from %s (%s): %s", "UDP_INFO", c->name, c->hostname, "invalid name");
		return false;
	}

	node_t *from = lookup_node(from_name);

	if(!from) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Got %s from %s (%s) origin %s which does not exist in our connection list", "UDP_INFO", c->name, c->hostname, from_name);
		return true;
	}

	if(from != from->via) {
		/* Not supposed to happen, as it means the message wandered past a static relay */
		logger(DEBUG_PROTOCOL, LOG_WARNING, "Got UDP info message from %s (%s) which we can't reach directly", from->name, from->hostname);
		return true;
	}

	/* If we have a direct edge to "from", we are in a better position
	   to guess its address than it is itself. */
	if(!from->connection && !from->status.udp_confirmed) {
		sockaddr_t from_addr = str2sockaddr(from_address, from_port);

		if(sockaddrcmp(&from_addr, &from->address)) {
			update_node_udp(from, &from_addr);
		}
	}

	node_t *to = lookup_node(to_name);

	if(!to) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Got %s from %s (%s) destination %s which does not exist in our connection list", "UDP_INFO", c->name, c->hostname, to_name);
		return true;
	}

	/* Send our own data (which could be what we just received) up the chain. */

	return send_udp_info(from, to);
}

/* Transmitting MTU information */

bool send_mtu_info(node_t *from, node_t *to, int mtu) {
	/* Skip cases where sending MTU info messages doesn't make sense.
	   This is done here in order to avoid repeating the same logic in multiple callsites. */

	if(to == myself) {
		return true;
	}

	if(!to->status.reachable) {
		return true;
	}

	if(from == myself) {
		if(to->connection) {
			return true;
		}

		struct timeval elapsed;

		timersub(&now, &to->mtu_info_sent, &elapsed);

		if(elapsed.tv_sec < mtu_info_interval) {
			return true;
		}
	}

	if((to->nexthop->options >> 24) < 6) {
		return true;
	}

	/* We will send the passed-in MTU value, unless we believe ours is better. */

	node_t *via = (from->via == myself) ? from->nexthop : from->via;

	if(from->minmtu == from->maxmtu && from->via == myself) {
		/* We have a direct measurement. Override the value entirely.
		   Note that we only do that if we are sitting as a static relay in the path;
		   otherwise, we can't guarantee packets will flow through us, and increasing
		   MTU could therefore end up being too optimistic. */
		mtu = from->minmtu;
	} else if(via->minmtu == via->maxmtu) {
		/* Static relay. Ensure packets will make it through the entire relay path. */
		mtu = MIN(mtu, via->minmtu);
	} else if(via->nexthop->minmtu == via->nexthop->maxmtu) {
		/* Dynamic relay. Ensure packets will make it through the entire relay path. */
		mtu = MIN(mtu, via->nexthop->minmtu);
	}

	if(from == myself) {
		to->mtu_info_sent = now;
	}

	/* If none of the conditions above match in the steady state, it means we're using TCP,
	   so the MTU is irrelevant. That said, it is still important to honor the MTU that was passed in,
	   because other parts of the relay path might be able to use UDP, which means they care about the MTU. */

	return send_request(to->nexthop->connection, "%d %s %s %d", MTU_INFO, from->name, to->name, mtu);
}

bool mtu_info_h(connection_t *c, const char *request) {
	char from_name[MAX_STRING_SIZE];
	char to_name[MAX_STRING_SIZE];
	int mtu;

	if(sscanf(request, "%*d "MAX_STRING" "MAX_STRING" %d", from_name, to_name, &mtu) != 3) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Got bad %s from %s (%s)", "MTU_INFO", c->name, c->hostname);
		return false;
	}

	if(mtu < 512) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Got bad %s from %s (%s): %s", "MTU_INFO", c->name, c->hostname, "invalid MTU");
		return false;
	}

	mtu = MIN(mtu, MTU);

	if(!check_id(from_name) || !check_id(to_name)) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Got bad %s from %s (%s): %s", "MTU_INFO", c->name, c->hostname, "invalid name");
		return false;
	}

	node_t *from = lookup_node(from_name);

	if(!from) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Got %s from %s (%s) origin %s which does not exist in our connection list", "MTU_INFO", c->name, c->hostname, from_name);
		return true;
	}

	/* If we don't know the current MTU for that node, use the one we received.
	   Even if we're about to make our own measurements, the value we got from downstream nodes should be pretty close
	   so it's a good idea to use it in the mean time. */
	if(from->mtu != mtu && from->minmtu != from->maxmtu) {
		logger(DEBUG_TRAFFIC, LOG_INFO, "Using provisional MTU %d for node %s (%s)", mtu, from->name, from->hostname);
		from->mtu = mtu;
	}

	node_t *to = lookup_node(to_name);

	if(!to) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Got %s from %s (%s) destination %s which does not exist in our connection list", "MTU_INFO", c->name, c->hostname, to_name);
		return true;
	}

	/* Continue passing the MTU value (or a better one if we have it) up the chain. */

	return send_mtu_info(from, to, mtu);
}
