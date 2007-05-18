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
extern char *controlfilename;

static void handle_control_data(int fd, short events, void *event) {
	char buf[MAXBUFSIZE];
	size_t inlen;

	inlen = read(fd, buf, sizeof buf);

	if(inlen <= 0) {
		logger(LOG_DEBUG, _("Closing control socket"));
		event_del(event);
		splay_delete(control_socket_tree, event);
		close(fd);
	}
}

static void handle_new_control_socket(int fd, short events, void *data) {
	int newfd;
	struct event *ev;

	newfd = accept(fd, NULL, NULL);

	if(newfd < 0) {
		logger(LOG_ERR, _("Accepting a new connection failed: %s"), strerror(errno));
		event_del(&control_event);
		return;
	}

	ev = xmalloc(sizeof *ev);
	event_set(ev, newfd, EV_READ | EV_PERSIST, handle_control_data, ev);
	event_add(ev, NULL);
	splay_insert(control_socket_tree, ev);

	logger(LOG_DEBUG, _("Control socket connection accepted"));
}

static int control_compare(const struct event *a, const struct event *b) {
	return a < b ? -1 : a > b ? 1 : 0;
}

void init_control() {
	struct sockaddr_un addr;

	control_socket_tree = splay_alloc_tree((splay_compare_t)control_compare, (splay_action_t)free);

	if(strlen(controlfilename) >= sizeof addr.sun_path) {
		logger(LOG_ERR, _("Control socket filename too long!"));
		return;
	}

	memset(&addr, 0, sizeof addr);
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, controlfilename, sizeof addr.sun_path - 1);

	control_socket = socket(PF_UNIX, SOCK_STREAM, 0);

	if(control_socket < 0) {
		logger(LOG_ERR, _("Creating UNIX socket failed: %s"), strerror(errno));
		return;
	}

	unlink(controlfilename);
	if(bind(control_socket, (struct sockaddr *)&addr, sizeof addr) < 0) {
		logger(LOG_ERR, _("Can't bind to %s: %s\n"), controlfilename, strerror(errno));
		close(control_socket);
		return;
	}

	if(listen(control_socket, 3) < 0) {
		logger(LOG_ERR, _("Can't listen on %s: %s\n"), controlfilename, strerror(errno));
		close(control_socket);
		return;
	}

	event_set(&control_event, control_socket, EV_READ | EV_PERSIST, handle_new_control_socket, NULL);
	event_add(&control_event, NULL);
}

void exit_control() {
	if(control_socket >= 0) {
		event_del(&control_event);
		close(control_socket);
	}
}
