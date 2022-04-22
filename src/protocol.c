/*
    protocol.c -- handle the meta-protocol, basic functions
    Copyright (C) 1999-2005 Ivo Timmermans,
                  2000-2022 Guus Sliepen <guus@tinc-vpn.org>

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
#include "crypto.h"
#include "logger.h"
#include "meta.h"
#include "protocol.h"
#include "utils.h"
#include "xalloc.h"

bool tunnelserver = false;
bool strictsubnets = false;
bool experimental = true;

static inline bool is_valid_request(request_t req) {
	return req > ALL && req < LAST;
}

/* Request handlers */
const request_entry_t *get_request_entry(request_t req) {
	if(!is_valid_request(req)) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Invalid request %d", req);
		return NULL;
	}

	// Prevent user from accessing the table directly to always have bound checks
	static const request_entry_t request_entries[] = {
		[ID] = {id_h, "ID"},
		[METAKEY] = {metakey_h, "METAKEY"},
		[CHALLENGE] = {challenge_h, "CHALLENGE"},
		[CHAL_REPLY] = {chal_reply_h, "CHAL_REPLY"},
		[ACK] = {ack_h, "ACK"},
		[STATUS] = {NULL, "STATUS"},
		[ERROR] = {NULL, "ERROR"},
		[TERMREQ] = {termreq_h, "TERMREQ"},
		[PING] = {ping_h, "PING"},
		[PONG] = {pong_h, "PONG"},
		[ADD_SUBNET] = {add_subnet_h, "ADD_SUBNET"},
		[DEL_SUBNET] = {del_subnet_h, "DEL_SUBNET"},
		[ADD_EDGE] = {add_edge_h, "ADD_EDGE"},
		[DEL_EDGE] = {del_edge_h, "DEL_EDGE"},
		[KEY_CHANGED] = {key_changed_h, "KEY_CHANGED"},
		[REQ_KEY] = {req_key_h, "REQ_KEY"},
		[ANS_KEY] = {ans_key_h, "ANS_KEY"},
		[PACKET] = {tcppacket_h, "PACKET"},
		[CONTROL] = {control_h, "CONTROL"},
		/* Not "real" requests yet */
		[REQ_PUBKEY] = {NULL, "REQ_PUBKEY"},
		[ANS_PUBKEY] = {NULL, "ANS_PUBKEY"},
		[SPTPS_PACKET] = {sptps_tcppacket_h, "SPTPS_PACKET"},
		[UDP_INFO] = {udp_info_h, "UDP_INFO"},
		[MTU_INFO] = {mtu_info_h, "MTU_INFO"},
	};
	return &request_entries[req];
}

static int past_request_compare(const past_request_t *a, const past_request_t *b) {
	return strcmp(a->request, b->request);
}

static void free_past_request(past_request_t *r) {
	if(r) {
		free((char *)r->request);
		free(r);
	}
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
		logger(DEBUG_ALWAYS, LOG_ERR, "Output buffer overflow while sending request to %s (%s)",
		       c->name, c->hostname);
		return false;
	}

	int id = atoi(request);
	logger(DEBUG_META, LOG_DEBUG, "Sending %s to %s (%s): %s", get_request_entry(id)->name, c->name, c->hostname, request);

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
	logger(DEBUG_META, LOG_DEBUG, "Forwarding %s from %s (%s): %s", get_request_entry(atoi(request))->name, from->name, from->hostname, request);

	// Create a temporary newline-terminated copy of the request
	size_t len = strlen(request);
	const size_t tmplen = len + 1;
	char *tmp = alloca(tmplen);
	memcpy(tmp, request, len);
	tmp[len] = '\n';
	broadcast_meta(from, tmp, tmplen);
}

bool receive_request(connection_t *c, const char *request) {
	if(c->outgoing && proxytype == PROXY_HTTP && c->allow_request == ID) {
		if(!request[0] || request[0] == '\r') {
			return true;
		}

		if(!strncasecmp(request, "HTTP/1.1 ", 9)) {
			if(!strncmp(request + 9, "200", 3)) {
				logger(DEBUG_CONNECTIONS, LOG_DEBUG, "Proxy request granted");
				return true;
			} else {
				logger(DEBUG_ALWAYS, LOG_DEBUG, "Proxy request rejected: %s", request + 9);
				return false;
			}
		}
	}

	int reqno = atoi(request);

	if(reqno || *request == '0') {
		if(!is_valid_request(reqno) || !get_request_entry(reqno)->handler) {
			logger(DEBUG_META, LOG_DEBUG, "Unknown request from %s (%s): %s", c->name, c->hostname, request);
			return false;
		}

		const request_entry_t *entry = get_request_entry(reqno);
		logger(DEBUG_META, LOG_DEBUG, "Got %s from %s (%s): %s", entry->name, c->name, c->hostname, request);

		if((c->allow_request != ALL) && (c->allow_request != reqno)) {
			logger(DEBUG_ALWAYS, LOG_ERR, "Unauthorized request from %s (%s)", c->name, c->hostname);
			return false;
		}

		if(!entry->handler(c, request)) {
			/* Something went wrong. Probably scriptkiddies. Terminate. */

			if(reqno != TERMREQ) {
				logger(DEBUG_ALWAYS, LOG_ERR, "Error while processing %s from %s (%s)", entry->name, c->name, c->hostname);
			}

			return false;
		}
	} else {
		logger(DEBUG_ALWAYS, LOG_ERR, "Bogus data received from %s (%s)", c->name, c->hostname);
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
		logger(DEBUG_SCARY_THINGS, LOG_DEBUG, "Aging past requests: deleted %d, left %d", deleted, left);
	}

	if(left)
		timeout_set(&past_request_timeout, &(struct timeval) {
		10, jitter()
	});
}

bool seen_request(const char *request) {
	past_request_t *new, p = {0};

	p.request = request;

	if(splay_search(&past_request_tree, &p)) {
		logger(DEBUG_SCARY_THINGS, LOG_DEBUG, "Already seen request");
		return true;
	} else {
		new = xmalloc(sizeof(*new));
		new->request = xstrdup(request);
		new->firstseen = now.tv_sec;
		splay_insert(&past_request_tree, new);
		timeout_add(&past_request_timeout, age_past_requests, NULL, &(struct timeval) {
			10, jitter()
		});
		return false;
	}
}

void exit_requests(void) {
	splay_empty_tree(&past_request_tree);

	timeout_del(&past_request_timeout);
}
