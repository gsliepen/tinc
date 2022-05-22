/*
    event.c -- kqueue support for the BSD family
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

#include <sys/event.h>

#include "../event.h"
#include "../utils.h"
#include "../net.h"

static bool running = false;
static int kq = 0;

static inline void event_init(void) {
	if(!kq) {
		kq = kqueue();

		if(kq == -1) {
			logger(DEBUG_ALWAYS, LOG_EMERG, "Could not initialize kqueue: %s", strerror(errno));
			abort();
		}
	}
}

static void event_deinit(void) {
	if(kq) {
		close(kq);
		kq = 0;
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

	const struct kevent change[] = {
		{
			.ident = io->fd,
			.filter = EVFILT_READ,
			.flags = EV_RECEIPT | (flags & IO_READ ? EV_ADD : EV_DELETE),
			.udata = io,
		},
		{
			.ident = io->fd,
			.filter = EVFILT_WRITE,
			.flags = EV_RECEIPT | (flags & IO_WRITE ? EV_ADD : EV_DELETE),
			.udata = io,
		},
	};
	struct kevent result[2];

	if(kevent(kq, change, 2, result, 2, NULL) < 0) {
		logger(DEBUG_ALWAYS, LOG_EMERG, "kevent failed: %s", strerror(errno));
		abort();
	}

	int rerr = (int)result[0].data;
	int werr = (int)result[1].data;

	if((rerr && rerr != ENOENT) || (werr && werr != ENOENT)) {
		logger(DEBUG_ALWAYS, LOG_EMERG, "kevent errors: %s, %s", strerror(rerr), strerror(werr));
		abort();
	}

	if(!flags) {
		io_tree.generation++;
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
		struct kevent events[MAX_EVENTS_PER_LOOP];

		const struct timespec ts = {
			.tv_sec = tv->tv_sec,
			.tv_nsec = tv->tv_usec * 1000,
		};

		int n = kevent(kq, NULL, 0, events, MAX_EVENTS_PER_LOOP, &ts);

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
			const struct kevent *evt = &events[i];
			const io_t *io = evt->udata;

			if(evt->filter == EVFILT_WRITE) {
				io->cb(io->data, IO_WRITE);
			} else if(evt->filter == EVFILT_READ) {
				io->cb(io->data, IO_READ);
			} else {
				continue;
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
