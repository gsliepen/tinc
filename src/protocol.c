/*
    protocol.c -- handle the meta-protocol, basic functions
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

#include "conf.h"
#include "connection.h"
#include "logger.h"
#include "meta.h"
#include "protocol.h"
#include "xalloc.h"

bool tunnelserver = false;
bool strictsubnets = false;
bool experimental = true;

/* Jumptable for the request handlers */

static bool (*request_handlers[])(connection_t *, const char *) = {
	id_h, metakey_h, challenge_h, chal_reply_h, ack_h,
	NULL, NULL, termreq_h,
	ping_h, pong_h,
	add_subnet_h, del_subnet_h,
	add_edge_h, del_edge_h,
	key_changed_h, req_key_h, ans_key_h, tcppacket_h, control_h,
	NULL, NULL, /* Not "real" requests (yet) */
	sptps_tcppacket_h,
	udp_info_h, mtu_info_h,
};

/* Request names */

static char (*request_name[]) = {
	"ID", "METAKEY", "CHALLENGE", "CHAL_REPLY", "ACK",
	"STATUS", "ERROR", "TERMREQ",
	"PING", "PONG",
	"ADD_SUBNET", "DEL_SUBNET",
	"ADD_EDGE", "DEL_EDGE", "KEY_CHANGED", "REQ_KEY", "ANS_KEY", "PACKET", "CONTROL",
	"REQ_PUBKEY", "ANS_PUBKEY", "SPTPS_PACKET", "UDP_INFO", "MTU_INFO",
};

static int past_request_compare(const past_request_t *a, const past_request_t *b) {
	return strcmp(a->request, b->request);
}

static void free_past_request(past_request_t *r) {
	free((char *)r->request);
	free(r);
}

static splay_tree_t past_request_tree = {
	.compare = (splay_compare_t) past_request_compare,
	.delete = (splay_action_t) free_past_request,
};

/* Generic request routines - takes care of logging and error
   detection as well */

bool send_request(connection_t *c, const char *format, ...) {
	va_list args;
	char request[MAXBUFSIZE];
	int len;

	/* Use vsnprintf instead of vxasprintf: faster, no memory
	   fragmentation, cleanup is automatic, and there is a limit on the
	   input buffer anyway */

	va_start(args, format);
	len = vsnprintf(request, sizeof(request), format, args);
	request[sizeof(request) - 1] = 0;
	va_end(args);

	if(len < 0 || (size_t)len > sizeof(request) - 1) {
		logger(DEBUG_ALWAYS, LOG_ERR, _("Output buffer overflow while sending request to %s (%s)"),
		       c->name, c->hostname);
		return false;
	}

	int id = atoi(request);
	logger(DEBUG_META, LOG_DEBUG, _("Sending %s to %s (%s): %s"), request_name[id], c->name, c->hostname, request);

	request[len++] = '\n';

	if(c == everyone) {
		broadcast_meta(NULL, request, len);
		return true;
	} else {
		if(id) {
			return send_meta(c, request, len);
		} else {
			send_meta_raw(c, request, len);
			return true;
		}
	}
}

void forward_request(connection_t *from, const char *request) {
	logger(DEBUG_META, LOG_DEBUG, _("Forwarding %s from %s (%s): %s"), request_name[atoi(request)], from->name, from->hostname, request);

	// Create a temporary newline-terminated copy of the request
	size_t len = strlen(request);
	char tmp[len + 1];
	memcpy(tmp, request, len);
	tmp[len] = '\n';
	broadcast_meta(from, tmp, sizeof(tmp));
}

bool receive_request(connection_t *c, const char *request) {
	if(c->outgoing && proxytype == PROXY_HTTP && c->allow_request == ID) {
		if(!request[0] || request[0] == '\r') {
			return true;
		}

		if(!strncasecmp(request, "HTTP/1.1 ", 9)) {
			if(!strncmp(request + 9, "200", 3)) {
				logger(DEBUG_CONNECTIONS, LOG_DEBUG, _("Proxy request granted"));
				return true;
			} else {
				logger(DEBUG_ALWAYS, LOG_DEBUG, _("Proxy request rejected: %s"), request + 9);
				return false;
			}
		}
	}

	int reqno = atoi(request);

	if(reqno || *request == '0') {
		if((reqno < 0) || (reqno >= LAST) || !request_handlers[reqno]) {
			logger(DEBUG_META, LOG_DEBUG, _("Unknown request from %s (%s): %s"), c->name, c->hostname, request);
			return false;
		} else {
			logger(DEBUG_META, LOG_DEBUG, _("Got %s from %s (%s): %s"), request_name[reqno], c->name, c->hostname, request);
		}

		if((c->allow_request != ALL) && (c->allow_request != reqno)) {
			logger(DEBUG_ALWAYS, LOG_ERR, _("Unauthorized request from %s (%s)"), c->name, c->hostname);
			return false;
		}

		if(!request_handlers[reqno](c, request)) {
			/* Something went wrong. Probably scriptkiddies. Terminate. */

			if(reqno != TERMREQ) {
				logger(DEBUG_ALWAYS, LOG_ERR, _("Error while processing %s from %s (%s)"), request_name[reqno], c->name, c->hostname);
			}

			return false;
		}
	} else {
		logger(DEBUG_ALWAYS, LOG_ERR, _("Bogus data received from %s (%s)"), c->name, c->hostname);
		return false;
	}

	return true;
}

static timeout_t past_request_timeout;

static void age_past_requests(void *data) {
	(void)data;
	int left = 0, deleted = 0;

	for splay_each(past_request_t, p, &past_request_tree) {
		if(p->firstseen + pinginterval <= now.tv_sec) {
			splay_delete_node(&past_request_tree, node), deleted++;
		} else {
			left++;
		}
	}

	if(left || deleted) {
		logger(DEBUG_SCARY_THINGS, LOG_DEBUG, _("Aging past requests: deleted %d, left %d"), deleted, left);
	}

	if(left)
		timeout_set(&past_request_timeout, &(struct timeval) {
		10, rand() % 100000
	});
}

bool seen_request(const char *request) {
	past_request_t *new, p = {0};

	p.request = request;

	if(splay_search(&past_request_tree, &p)) {
		logger(DEBUG_SCARY_THINGS, LOG_DEBUG, _("Already seen request"));
		return true;
	} else {
		new = xmalloc(sizeof(*new));
		new->request = xstrdup(request);
		new->firstseen = now.tv_sec;
		splay_insert(&past_request_tree, new);
		timeout_add(&past_request_timeout, age_past_requests, NULL, &(struct timeval) {
			10, rand() % 100000
		});
		return false;
	}
}

void exit_requests(void) {
	splay_empty_tree(&past_request_tree);

	timeout_del(&past_request_timeout);
}
