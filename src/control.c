/*
    control.c -- Control socket handling.
    Copyright (C) 2007 Guus Sliepen <guus@tinc-vpn.org>

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
#include "control.h"
#include "control_common.h"
#include "graph.h"
#include "logger.h"
#include "utils.h"
#include "xalloc.h"

static int control_socket = -1;
static struct event control_event;
static splay_tree_t *control_socket_tree;
extern char *controlsocketname;

static void handle_control_data(struct bufferevent *event, void *data) {
	tinc_ctl_request_t req;
	tinc_ctl_request_t res;
	struct evbuffer *res_data = NULL;
	void *req_data;

	if(EVBUFFER_LENGTH(event->input) < sizeof req)
		return;

	/* Copy the structure to ensure alignment */
	memcpy(&req, EVBUFFER_DATA(event->input), sizeof req);

	if(EVBUFFER_LENGTH(event->input) < req.length)
		return;
	req_data = EVBUFFER_DATA(event->input) + sizeof req;

	if(req.length < sizeof req)
		goto failure;

	memset(&res, 0, sizeof res);
	res.type = req.type;
	res.id = req.id;

	res_data = evbuffer_new();
	if(res_data == NULL) {
		res.res_errno = ENOMEM;
		goto respond;
	}

	if(req.type == REQ_STOP) {
		logger(LOG_NOTICE, "Got '%s' command", "stop");
		event_loopexit(NULL);
		goto respond;
	}

	if(req.type == REQ_DUMP_NODES) {
		logger(LOG_NOTICE, "Got '%s' command", "dump nodes");
		res.res_errno = dump_nodes(res_data);
		goto respond;
	}

	if(req.type == REQ_DUMP_EDGES) {
		logger(LOG_NOTICE, "Got '%s' command", "dump edges");
		res.res_errno = dump_edges(res_data);
		goto respond;
	}

	if(req.type == REQ_DUMP_SUBNETS) {
		logger(LOG_NOTICE, "Got '%s' command", "dump subnets");
		res.res_errno = dump_subnets(res_data);
		goto respond;
	}

	if(req.type == REQ_DUMP_CONNECTIONS) {
		logger(LOG_NOTICE, "Got '%s' command", "dump connections");
		res.res_errno = dump_connections(res_data);
		goto respond;
	}

	if(req.type == REQ_DUMP_GRAPH) {
		logger(LOG_NOTICE, "Got '%s' command", "dump graph");
		res.res_errno = dump_graph(res_data);
		goto respond;
	}

	if(req.type == REQ_PURGE) {
		logger(LOG_NOTICE, "Got '%s' command", "purge");
		purge();
		goto respond;
	}

	if(req.type == REQ_SET_DEBUG) {
		debug_t new_debug_level;

		logger(LOG_NOTICE, "Got '%s' command", "debug");
		if(req.length != sizeof req + sizeof debug_level)
			res.res_errno = EINVAL;
		else {
			memcpy(&new_debug_level, req_data, sizeof new_debug_level);
			logger(LOG_NOTICE, "Changing debug level from %d to %d",
				   debug_level, new_debug_level);
			if(evbuffer_add_printf(res_data,
								   "Changing debug level from %d to %d\n",
								   debug_level, new_debug_level) == -1)
				res.res_errno = errno;
			debug_level = new_debug_level;
		}
		goto respond;
	}

	if(req.type == REQ_RETRY) {
		logger(LOG_NOTICE, "Got '%s' command", "retry");
		retry();
		goto respond;
	}

	if(req.type == REQ_RELOAD) {
		logger(LOG_NOTICE, "Got '%s' command", "reload");
		res.res_errno = reload_configuration();
		goto respond;
	}

	logger(LOG_DEBUG, "Malformed control command received");
	res.res_errno = EINVAL;

respond:
	res.length = (sizeof res)
				 + ((res_data == NULL) ? 0 : EVBUFFER_LENGTH(res_data));
	evbuffer_drain(event->input, req.length);
	if(bufferevent_write(event, &res, sizeof res) == -1)
		goto failure;
	if(res_data != NULL) {
		if(bufferevent_write_buffer(event, res_data) == -1)
			goto failure;
		evbuffer_free(res_data);
	}
	return;

failure:
	logger(LOG_INFO, "Closing control socket on error");
	evbuffer_free(res_data);
	close(event->ev_read.ev_fd);
	splay_delete(control_socket_tree, event);
}

static void handle_control_error(struct bufferevent *event, short what, void *data) {
	if(what & EVBUFFER_EOF)
		logger(LOG_DEBUG, "Control socket connection closed by peer");
	else
		logger(LOG_DEBUG, "Error while reading from control socket: %s", strerror(errno));

	close(event->ev_read.ev_fd);
	splay_delete(control_socket_tree, event);
}

static void handle_new_control_socket(int fd, short events, void *data) {
	int newfd;
	struct bufferevent *ev;
	tinc_ctl_greeting_t greeting;

	newfd = accept(fd, NULL, NULL);

	if(newfd < 0) {
		logger(LOG_ERR, "Accepting a new connection failed: %s", strerror(errno));
		event_del(&control_event);
		return;
	}

	ev = bufferevent_new(newfd, handle_control_data, NULL, handle_control_error, NULL);
	if(!ev) {
		logger(LOG_ERR, "Could not create bufferevent for new control connection: %s", strerror(errno));
		close(newfd);
		return;
	}

	memset(&greeting, 0, sizeof greeting);
	greeting.version = TINC_CTL_VERSION_CURRENT;
	greeting.pid = getpid();
	if(bufferevent_write(ev, &greeting, sizeof greeting) == -1) {
		logger(LOG_ERR,
			   "Cannot send greeting for new control connection: %s",
			   strerror(errno));
		bufferevent_free(ev);
		close(newfd);
		return;
	}

	bufferevent_enable(ev, EV_READ);
	splay_insert(control_socket_tree, ev);

	logger(LOG_DEBUG, "Control socket connection accepted");
}

static int control_compare(const struct event *a, const struct event *b) {
	return a < b ? -1 : a > b ? 1 : 0;
}

bool init_control() {
	int result;

#ifdef HAVE_MINGW
	struct sockaddr_in addr;
	memset(&addr, 0, sizeof addr);
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(0x7f000001);
	addr.sin_port = htons(55555);
	int option = 1;

	control_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if(control_socket < 0) {
		logger(LOG_ERR, "Creating control socket failed: %s", sockstrerror(sockerrno));
		goto bail;
	}

	setsockopt(control_socket, SOL_SOCKET, SO_REUSEADDR, &option, sizeof option);
#else
	struct sockaddr_un addr;
	char *lastslash;

	if(strlen(controlsocketname) >= sizeof addr.sun_path) {
		logger(LOG_ERR, "Control socket filename too long!");
		goto bail;
	}

	memset(&addr, 0, sizeof addr);
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, controlsocketname, sizeof addr.sun_path - 1);

	control_socket = socket(PF_UNIX, SOCK_STREAM, 0);

	if(control_socket < 0) {
		logger(LOG_ERR, "Creating UNIX socket failed: %s", strerror(errno));
		goto bail;
	}

	/*
	 * Restrict connections to our control socket by ensuring the parent
	 * directory can be traversed only by root. Note this is not totally
	 * race-free unless all ancestors are writable only by trusted users,
	 * which we don't verify.
	 */

	struct stat statbuf;
	lastslash = strrchr(controlsocketname, '/');
	if(lastslash != NULL) {
		*lastslash = 0; /* temporarily change controlsocketname to be dir */
		if(mkdir(controlsocketname, 0700) < 0 && errno != EEXIST) {
			logger(LOG_ERR, "Unable to create control socket directory %s: %s", controlsocketname, strerror(errno));
			*lastslash = '/';
			goto bail;
		}

		result = stat(controlsocketname, &statbuf);
		*lastslash = '/';
	} else
		result = stat(".", &statbuf);

	if(result < 0) {
		logger(LOG_ERR, "Examining control socket directory failed: %s", strerror(errno));
		goto bail;
	}

	if(statbuf.st_uid != 0 || (statbuf.st_mode & S_IXOTH) != 0 || (statbuf.st_gid != 0 && (statbuf.st_mode & S_IXGRP)) != 0) {
		logger(LOG_ERR, "Control socket directory ownership/permissions insecure.");
		goto bail;
	}
#endif

	result = bind(control_socket, (struct sockaddr *)&addr, sizeof addr);

	if(result < 0 && sockinuse(sockerrno)) {
#ifndef HAVE_MINGW
		result = connect(control_socket, (struct sockaddr *)&addr, sizeof addr);
		if(result < 0) {
			logger(LOG_WARNING, "Removing old control socket.");
			unlink(controlsocketname);
			result = bind(control_socket, (struct sockaddr *)&addr, sizeof addr);
		} else
#endif
		{
			if(netname)
				logger(LOG_ERR, "Another tincd is already running for net `%s'.", netname);
			else
				logger(LOG_ERR, "Another tincd is already running.");
			goto bail;
		}
	}

	if(result < 0) {
		logger(LOG_ERR, "Can't bind to %s: %s", controlsocketname, strerror(errno));
		goto bail;
	}

	if(listen(control_socket, 3) < 0) {
		logger(LOG_ERR, "Can't listen on %s: %s", controlsocketname, strerror(errno));
		goto bail;
	}

	control_socket_tree = splay_alloc_tree((splay_compare_t)control_compare, (splay_action_t)bufferevent_free);

	event_set(&control_event, control_socket, EV_READ | EV_PERSIST, handle_new_control_socket, NULL);
	event_add(&control_event, NULL);
	return true;

bail:
	if(control_socket != -1) {
		closesocket(control_socket);
		control_socket = -1;
	}
	return false;
}

void exit_control() {
	event_del(&control_event);
	closesocket(control_socket);
	unlink(controlsocketname);
}
