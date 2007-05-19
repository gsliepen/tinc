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

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.

    $Id$
*/

#include <sys/un.h>

#include "system.h"
#include "conf.h"
#include "control.h"
#include "logger.h"
#include "xalloc.h"

static int control_socket = -1;
static struct event control_event;
static splay_tree_t *control_socket_tree;
extern char *controlsocketname;

static void handle_control_data(struct bufferevent *event, void *data) {
	char *line = evbuffer_readline(event->input);
	if(!line)
		return;
	
	if(!strcasecmp(line, "stop")) {
		logger(LOG_NOTICE, _("Got stop command"));
		event_loopexit(NULL);
		return;
	}

	logger(LOG_DEBUG, _("Malformed control command received"));
	close(event->ev_read.ev_fd);
	splay_delete(control_socket_tree, event);
}

static void handle_control_error(struct bufferevent *event, short what, void *data) {
	if(what & EVBUFFER_EOF)
		logger(LOG_DEBUG, _("Control socket connection closed by peer"));
	else
		logger(LOG_DEBUG, _("Error while reading from control socket: %s"), strerror(errno));

	close(event->ev_read.ev_fd);
	splay_delete(control_socket_tree, event);
}

static void handle_new_control_socket(int fd, short events, void *data) {
	int newfd;
	struct bufferevent *ev;

	newfd = accept(fd, NULL, NULL);

	if(newfd < 0) {
		logger(LOG_ERR, _("Accepting a new connection failed: %s"), strerror(errno));
		event_del(&control_event);
		return;
	}

	ev = bufferevent_new(newfd, handle_control_data, NULL, handle_control_error, NULL);
	if(!ev) {
		logger(LOG_ERR, _("Could not create bufferevent for new control connection: %s"), strerror(errno));
		close(newfd);
		return;
	}

	bufferevent_enable(ev, EV_READ);
	splay_insert(control_socket_tree, ev);

	logger(LOG_DEBUG, _("Control socket connection accepted"));
}

static int control_compare(const struct event *a, const struct event *b) {
	return a < b ? -1 : a > b ? 1 : 0;
}

bool init_control() {
	int result;
	struct sockaddr_un addr;

	if(strlen(controlsocketname) >= sizeof addr.sun_path) {
		logger(LOG_ERR, _("Control socket filename too long!"));
		return false;
	}

	memset(&addr, 0, sizeof addr);
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, controlsocketname, sizeof addr.sun_path - 1);

	control_socket = socket(PF_UNIX, SOCK_STREAM, 0);

	if(control_socket < 0) {
		logger(LOG_ERR, _("Creating UNIX socket failed: %s"), strerror(errno));
		return false;
	}

	//unlink(controlsocketname);
	result = bind(control_socket, (struct sockaddr *)&addr, sizeof addr);
	
	if(result < 0 && errno == EADDRINUSE) {
		result = connect(control_socket, (struct sockaddr *)&addr, sizeof addr);
		if(result < 0) {
			logger(LOG_WARNING, _("Removing old control socket."));
			unlink(controlsocketname);
			result = bind(control_socket, (struct sockaddr *)&addr, sizeof addr);
		} else {
			close(control_socket);
			if(netname)
				logger(LOG_ERR, _("Another tincd is already running for net `%s'."), netname);
			else
				logger(LOG_ERR, _("Another tincd is already running."));
			return false;
		}
	}

	if(result < 0) {
		logger(LOG_ERR, _("Can't bind to %s: %s\n"), controlsocketname, strerror(errno));
		close(control_socket);
		return false;
	}

	if(listen(control_socket, 3) < 0) {
		logger(LOG_ERR, _("Can't listen on %s: %s\n"), controlsocketname, strerror(errno));
		close(control_socket);
		return false;
	}

	control_socket_tree = splay_alloc_tree((splay_compare_t)control_compare, (splay_action_t)bufferevent_free);

	event_set(&control_event, control_socket, EV_READ | EV_PERSIST, handle_new_control_socket, NULL);
	event_add(&control_event, NULL);

	return true;
}

void exit_control() {
	event_del(&control_event);
	close(control_socket);
	unlink(controlsocketname);
}
