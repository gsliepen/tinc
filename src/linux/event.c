/*
    event.c -- epoll support for Linux
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

#include "../system.h"

#include <sys/epoll.h>

#include "../event.h"
#include "../utils.h"
#include "../net.h"

static bool running = false;
static int epollset = 0;

/* NOTE: 1024 limit is only used on ancient (pre 2.6.27) kernels.
   Decent kernels will ignore this value making it unlimited.
   epoll_create1 might be better, but these kernels would not be supported
   in that case. */
static inline void event_init(void) {
	if(!epollset) {
		epollset = epoll_create(1024);

		if(epollset == -1) {
			logger(DEBUG_ALWAYS, LOG_EMERG, "Could not initialize epoll: %s", strerror(errno));
			abort();
		}
	}
}

static void event_deinit(void) {
	if(epollset) {
		close(epollset);
		epollset = 0;
	}
}

void io_add(io_t *io, io_cb_t cb, void *data, int fd, int flags) {
	if(io->cb) {
		return;
	}

	io->fd = fd;
	io->cb = cb;
	io->data = data;
	io->node.data = io;

	io_set(io, flags);
}

void io_set(io_t *io, int flags) {
	event_init();

	if(flags == io->flags) {
		return;
	}

	io->flags = flags;

	if(io->fd == -1) {
		return;
	}

	epoll_ctl(epollset, EPOLL_CTL_DEL, io->fd, NULL);

	struct epoll_event ev = {
		.events = 0,
		.data.ptr = io,
	};

	if(flags & IO_READ) {
		ev.events |= EPOLLIN;
	}

	if(flags & IO_WRITE) {
		ev.events |= EPOLLOUT;
	} else if(ev.events == 0) {
		io_tree.generation++;
		return;
	}

	if(epoll_ctl(epollset, EPOLL_CTL_ADD, io->fd, &ev) < 0) {
		logger(DEBUG_ALWAYS, LOG_EMERG, "epoll_ctl failed: %s", strerror(errno));
		abort();
	}
}

void io_del(io_t *io) {
	if(io->cb) {
		io_set(io, 0);
		io->cb = NULL;
	}
}

bool event_loop(void) {
	event_init();
	running = true;

	while(running) {
		struct timeval diff;
		struct timeval *tv = timeout_execute(&diff);

		struct epoll_event events[MAX_EVENTS_PER_LOOP];
		long timeout = (tv->tv_sec * 1000) + (tv->tv_usec / 1000);

		if(timeout > INT_MAX) {
			timeout = INT_MAX;
		}

		int n = epoll_wait(epollset, events, MAX_EVENTS_PER_LOOP, (int)timeout);

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

		for(int i = 0; i < n; i++) {
			io_t *io = events[i].data.ptr;

			if(events[i].events & EPOLLOUT && io->flags & IO_WRITE) {
				io->cb(io->data, IO_WRITE);
			}

			if(curgen != io_tree.generation) {
				break;
			}

			if(events[i].events & EPOLLIN && io->flags & IO_READ) {
				io->cb(io->data, IO_READ);
			}

			if(curgen != io_tree.generation) {
				break;
			}
		}

	}

	event_deinit();
	return true;
}

void event_exit(void) {
	running = false;
}
