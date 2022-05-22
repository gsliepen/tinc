/*
    event_select.c -- select(2) support
    Copyright (C) 2012-2022 Guus Sliepen <guus@tinc-vpn.org>

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

#include "event.h"
#include "utils.h"

static bool running = false;
static fd_set readfds;
static fd_set writefds;

void io_add(io_t *io, io_cb_t cb, void *data, int fd, int flags) {
	if(io->cb) {
		return;
	}

	io->fd = fd;
	io->cb = cb;
	io->data = data;
	io->node.data = io;

	io_set(io, flags);

	if(!splay_insert_node(&io_tree, &io->node)) {
		abort();
	}
}

void io_set(io_t *io, int flags) {
	if(flags == io->flags) {
		return;
	}

	io->flags = flags;

	if(io->fd == -1) {
		return;
	}

	if(flags & IO_READ) {
		FD_SET(io->fd, &readfds);
	} else {
		FD_CLR(io->fd, &readfds);
	}

	if(flags & IO_WRITE) {
		FD_SET(io->fd, &writefds);
	} else {
		FD_CLR(io->fd, &writefds);
	}
}

void io_del(io_t *io) {
	if(io->cb) {
		io_set(io, 0);
		splay_unlink_node(&io_tree, &io->node);
		io->cb = NULL;
	}
}

bool event_loop(void) {
	running = true;

	fd_set readable;
	fd_set writable;

	while(running) {
		struct timeval diff;
		struct timeval *tv = timeout_execute(&diff);

		memcpy(&readable, &readfds, sizeof(readable));
		memcpy(&writable, &writefds, sizeof(writable));

		int maxfds =  0;

		if(io_tree.tail) {
			io_t *last = io_tree.tail->data;
			maxfds = last->fd + 1;
		}

		int n = select(maxfds, &readable, &writable, NULL, tv);

		if(n < 0) {
			if(sockwouldblock(sockerrno)) {
				continue;
			} else {
				return false;
			}
		}

		if(!n) {
			continue;
		}

		unsigned int curgen = io_tree.generation;

		for splay_each(io_t, io, &io_tree) {
			if(FD_ISSET(io->fd, &writable)) {
				io->cb(io->data, IO_WRITE);
			} else if(FD_ISSET(io->fd, &readable)) {
				io->cb(io->data, IO_READ);
			} else {
				continue;
			}

			/*
			    There are scenarios in which the callback will remove another io_t from the tree
			    (e.g. closing a double connection). Since splay_each does not support that, we
			    need to exit the loop if that happens. That's okay, since any remaining events will
			    get picked up by the next select() call.
			*/
			if(curgen != io_tree.generation) {
				break;
			}
		}
	}

	return true;
}

void event_exit(void) {
	running = false;
}
