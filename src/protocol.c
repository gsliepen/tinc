/*
    protocol.c -- handle the meta-protocol, basic functions
    Copyright (C) 1999-2005 Ivo Timmermans,
                  2000-2009 Guus Sliepen <guus@tinc-vpn.org>

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
#include "utils.h"
#include "xalloc.h"

bool tunnelserver = false;
bool strictsubnets = false;
bool experimental = false;

/* Jumptable for the request handlers */

static bool (*request_handlers[])(connection_t *, char *) = {
		id_h, metakey_h, challenge_h, chal_reply_h, ack_h,
		status_h, error_h, termreq_h,
		ping_h, pong_h,
		add_subnet_h, del_subnet_h,
		add_edge_h, del_edge_h,
		key_changed_h, req_key_h, ans_key_h, tcppacket_h, control_h,
};

/* Request names */

static char (*request_name[]) = {
		"ID", "METAKEY", "CHALLENGE", "CHAL_REPLY", "ACK",
		"STATUS", "ERROR", "TERMREQ",
		"PING", "PONG",
		"ADD_SUBNET", "DEL_SUBNET",
		"ADD_EDGE", "DEL_EDGE", "KEY_CHANGED", "REQ_KEY", "ANS_KEY", "PACKET", "CONTROL",
};

static splay_tree_t *past_request_tree;

bool check_id(const char *id) {
	for(; *id; id++)
		if(!isalnum(*id) && *id != '_')
			return false;

	return true;
}

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
	len = vsnprintf(request, MAXBUFSIZE, format, args);
	va_end(args);

	if(len < 0 || len > MAXBUFSIZE - 1) {
		logger(LOG_ERR, "Output buffer overflow while sending request to %s (%s)",
			   c->name, c->hostname);
		return false;
	}

	ifdebug(PROTOCOL) {
		ifdebug(META)
			logger(LOG_DEBUG, "Sending %s to %s (%s): %s",
				   request_name[atoi(request)], c->name, c->hostname, request);
		else
			logger(LOG_DEBUG, "Sending %s to %s (%s)", request_name[atoi(request)],
				   c->name, c->hostname);
	}

	request[len++] = '\n';

	if(c == broadcast) {
		broadcast_meta(NULL, request, len);
		return true;
	} else
		return send_meta(c, request, len);
}

void forward_request(connection_t *from, char *request) {
	/* Note: request is not zero terminated anymore after a call to this function! */
	ifdebug(PROTOCOL) {
		ifdebug(META)
			logger(LOG_DEBUG, "Forwarding %s from %s (%s): %s",
				   request_name[atoi(request)], from->name, from->hostname, request);
		else
			logger(LOG_DEBUG, "Forwarding %s from %s (%s)",
				   request_name[atoi(request)], from->name, from->hostname);
	}

	int len = strlen(request);
	request[len++] = '\n';
	broadcast_meta(from, request, len);
}

bool receive_request(connection_t *c, char *request) {
	int reqno = atoi(request);

	if(reqno || *request == '0') {
		if((reqno < 0) || (reqno >= LAST) || !request_handlers[reqno]) {
			ifdebug(META)
				logger(LOG_DEBUG, "Unknown request from %s (%s): %s",
					   c->name, c->hostname, request);
			else
				logger(LOG_ERR, "Unknown request from %s (%s)",
					   c->name, c->hostname);

			return false;
		} else {
			ifdebug(PROTOCOL) {
				ifdebug(META)
					logger(LOG_DEBUG, "Got %s from %s (%s): %s",
						   request_name[reqno], c->name, c->hostname, request);
				else
					logger(LOG_DEBUG, "Got %s from %s (%s)",
						   request_name[reqno], c->name, c->hostname);
			}
		}

		if((c->allow_request != ALL) && (c->allow_request != reqno)) {
			logger(LOG_ERR, "Unauthorized request from %s (%s)", c->name,
				   c->hostname);
			return false;
		}

		if(!request_handlers[reqno](c, request)) {
			/* Something went wrong. Probably scriptkiddies. Terminate. */

			logger(LOG_ERR, "Error while processing %s from %s (%s)",
				   request_name[reqno], c->name, c->hostname);
			return false;
		}
	} else {
		logger(LOG_ERR, "Bogus data received from %s (%s)",
			   c->name, c->hostname);
		return false;
	}

	return true;
}

static int past_request_compare(const past_request_t *a, const past_request_t *b) {
	return strcmp(a->request, b->request);
}

static void free_past_request(past_request_t *r) {
	if(r->request)
		free(r->request);

	free(r);
}

static struct event past_request_event;

bool seen_request(char *request) {
	past_request_t *new, p = {NULL};

	p.request = request;

	if(splay_search(past_request_tree, &p)) {
		ifdebug(SCARY_THINGS) logger(LOG_DEBUG, "Already seen request");
		return true;
	} else {
		new = xmalloc(sizeof *new);
		new->request = xstrdup(request);
		new->firstseen = time(NULL);
		splay_insert(past_request_tree, new);
		event_add(&past_request_event, &(struct timeval){10, 0});
		return false;
	}
}

static void age_past_requests(int fd, short events, void *data) {
	splay_node_t *node, *next;
	past_request_t *p;
	int left = 0, deleted = 0;
	time_t now = time(NULL);

	for(node = past_request_tree->head; node; node = next) {
		next = node->next;
		p = node->data;

		if(p->firstseen + pinginterval <= now)
			splay_delete_node(past_request_tree, node), deleted++;
		else
			left++;
	}

	if(left || deleted)
		ifdebug(SCARY_THINGS) logger(LOG_DEBUG, "Aging past requests: deleted %d, left %d",
			   deleted, left);

	if(left)
		event_add(&past_request_event, &(struct timeval){10, 0});
}

void init_requests(void) {
	past_request_tree = splay_alloc_tree((splay_compare_t) past_request_compare, (splay_action_t) free_past_request);

	timeout_set(&past_request_event, age_past_requests, NULL);
}

void exit_requests(void) {
	splay_delete_tree(past_request_tree);

	if(timeout_initialized(&past_request_event))
		event_del(&past_request_event);
}
