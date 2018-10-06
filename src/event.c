/*
    event.c -- I/O, timeout and signal event handling
    Copyright (C) 2012-2013 Guus Sliepen <guus@tinc-vpn.org>

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

#include "dropin.h"
#include "event.h"
#include "net.h"
#include "utils.h"
#include "xalloc.h"

struct timeval now;

#ifndef HAVE_MINGW
static fd_set readfds;
static fd_set writefds;
#else
static const long READ_EVENTS = FD_READ | FD_ACCEPT | FD_CLOSE;
static const long WRITE_EVENTS = FD_WRITE | FD_CONNECT;
static DWORD event_count = 0;
#endif
static bool running;

static int io_compare(const io_t *a, const io_t *b) {
#ifndef HAVE_MINGW
	return a->fd - b->fd;
#else

	if(a->event < b->event) {
		return -1;
	}

	if(a->event > b->event) {
		return 1;
	}

	return 0;
#endif
}

static int timeout_compare(const timeout_t *a, const timeout_t *b) {
	struct timeval diff;
	timersub(&a->tv, &b->tv, &diff);

	if(diff.tv_sec < 0) {
		return -1;
	}

	if(diff.tv_sec > 0) {
		return 1;
	}

	if(diff.tv_usec < 0) {
		return -1;
	}

	if(diff.tv_usec > 0) {
		return 1;
	}

	if(a < b) {
		return -1;
	}

	if(a > b) {
		return 1;
	}

	return 0;
}

static splay_tree_t io_tree = {.compare = (splay_compare_t)io_compare};
static splay_tree_t timeout_tree = {.compare = (splay_compare_t)timeout_compare};

void io_add(io_t *io, io_cb_t cb, void *data, int fd, int flags) {
	if(io->cb) {
		return;
	}

	io->fd = fd;
#ifdef HAVE_MINGW

	if(io->fd != -1) {
		io->event = WSACreateEvent();

		if(io->event == WSA_INVALID_EVENT) {
			abort();
		}
	}

	event_count++;
#endif
	io->cb = cb;
	io->data = data;
	io->node.data = io;

	io_set(io, flags);

	if(!splay_insert_node(&io_tree, &io->node)) {
		abort();
	}
}

#ifdef HAVE_MINGW
void io_add_event(io_t *io, io_cb_t cb, void *data, WSAEVENT event) {
	io->event = event;
	io_add(io, cb, data, -1, 0);
}
#endif

void io_set(io_t *io, int flags) {
	if(flags == io->flags) {
		return;
	}

	io->flags = flags;

	if(io->fd == -1) {
		return;
	}

#ifndef HAVE_MINGW

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

#else
	long events = 0;

	if(flags & IO_WRITE) {
		events |= WRITE_EVENTS;
	}

	if(flags & IO_READ) {
		events |= READ_EVENTS;
	}

	if(WSAEventSelect(io->fd, io->event, events) != 0) {
		abort();
	}

#endif
}

void io_del(io_t *io) {
	if(!io->cb) {
		return;
	}

	io_set(io, 0);
#ifdef HAVE_MINGW

	if(io->fd != -1 && WSACloseEvent(io->event) == FALSE) {
		abort();
	}

	event_count--;
#endif

	splay_unlink_node(&io_tree, &io->node);
	io->cb = NULL;
}

void timeout_add(timeout_t *timeout, timeout_cb_t cb, void *data, struct timeval *tv) {
	timeout->cb = cb;
	timeout->data = data;
	timeout->node.data = timeout;

	timeout_set(timeout, tv);
}

void timeout_set(timeout_t *timeout, struct timeval *tv) {
	if(timerisset(&timeout->tv)) {
		splay_unlink_node(&timeout_tree, &timeout->node);
	}

	if(!now.tv_sec) {
		gettimeofday(&now, NULL);
	}

	timeradd(&now, tv, &timeout->tv);

	if(!splay_insert_node(&timeout_tree, &timeout->node)) {
		abort();
	}
}

void timeout_del(timeout_t *timeout) {
	if(!timeout->cb) {
		return;
	}

	splay_unlink_node(&timeout_tree, &timeout->node);
	timeout->cb = 0;
	timeout->tv = (struct timeval) {
		0, 0
	};
}

#ifndef HAVE_MINGW
static int signal_compare(const signal_t *a, const signal_t *b) {
	return a->signum - b->signum;
}

static io_t signalio;
static int pipefd[2] = {-1, -1};
static splay_tree_t signal_tree = {.compare = (splay_compare_t)signal_compare};

static void signal_handler(int signum) {
	unsigned char num = signum;
	write(pipefd[1], &num, 1);
}

static void signalio_handler(void *data, int flags) {
	(void)data;
	(void)flags;
	unsigned char signum;

	if(read(pipefd[0], &signum, 1) != 1) {
		return;
	}

	signal_t *sig = splay_search(&signal_tree, &((signal_t) {
		.signum = signum
	}));

	if(sig) {
		sig->cb(sig->data);
	}
}

static void pipe_init(void) {
	if(!pipe(pipefd)) {
		io_add(&signalio, signalio_handler, NULL, pipefd[0], IO_READ);
	}
}

void signal_add(signal_t *sig, signal_cb_t cb, void *data, int signum) {
	if(sig->cb) {
		return;
	}

	sig->cb = cb;
	sig->data = data;
	sig->signum = signum;
	sig->node.data = sig;

	if(pipefd[0] == -1) {
		pipe_init();
	}

	signal(sig->signum, signal_handler);

	if(!splay_insert_node(&signal_tree, &sig->node)) {
		abort();
	}
}

void signal_del(signal_t *sig) {
	if(!sig->cb) {
		return;
	}

	signal(sig->signum, SIG_DFL);

	splay_unlink_node(&signal_tree, &sig->node);
	sig->cb = NULL;
}
#endif

static struct timeval *get_time_remaining(struct timeval *diff) {
	gettimeofday(&now, NULL);
	struct timeval *tv = NULL;

	while(timeout_tree.head) {
		timeout_t *timeout = timeout_tree.head->data;
		timersub(&timeout->tv, &now, diff);

		if(diff->tv_sec < 0) {
			timeout->cb(timeout->data);

			if(timercmp(&timeout->tv, &now, <)) {
				timeout_del(timeout);
			}
		} else {
			tv = diff;
			break;
		}
	}

	return tv;
}

bool event_loop(void) {
	running = true;

#ifndef HAVE_MINGW
	fd_set readable;
	fd_set writable;

	while(running) {
		struct timeval diff;
		struct timeval *tv = get_time_remaining(&diff);
		memcpy(&readable, &readfds, sizeof(readable));
		memcpy(&writable, &writefds, sizeof(writable));

		int fds = 0;

		if(io_tree.tail) {
			io_t *last = io_tree.tail->data;
			fds = last->fd + 1;
		}

		int n = select(fds, &readable, &writable, NULL, tv);

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

#else

	while(running) {
		struct timeval diff;
		struct timeval *tv = get_time_remaining(&diff);
		DWORD timeout_ms = tv ? (tv->tv_sec * 1000 + tv->tv_usec / 1000 + 1) : WSA_INFINITE;

		if(!event_count) {
			Sleep(timeout_ms);
			continue;
		}

		/*
		   For some reason, Microsoft decided to make the FD_WRITE event edge-triggered instead of level-triggered,
		   which is the opposite of what select() does. In practice, that means that if a FD_WRITE event triggers,
		   it will never trigger again until a send() returns EWOULDBLOCK. Since the semantics of this event loop
		   is that write events are level-triggered (i.e. they continue firing until the socket is full), we need
		   to emulate these semantics by making sure we fire each IO_WRITE that is still writeable.

		   Note that technically FD_CLOSE has the same problem, but it's okay because user code does not rely on
		   this event being fired again if ignored.
		*/
		unsigned int curgen = io_tree.generation;

		for splay_each(io_t, io, &io_tree) {
			if(io->flags & IO_WRITE && send(io->fd, NULL, 0, 0) == 0) {
				io->cb(io->data, IO_WRITE);

				if(curgen != io_tree.generation) {
					break;
				}
			}
		}

		if(event_count > WSA_MAXIMUM_WAIT_EVENTS) {
			WSASetLastError(WSA_INVALID_PARAMETER);
			return(false);
		}

		WSAEVENT events[WSA_MAXIMUM_WAIT_EVENTS];
		io_t *io_map[WSA_MAXIMUM_WAIT_EVENTS];
		DWORD event_index = 0;

		for splay_each(io_t, io, &io_tree) {
			events[event_index] = io->event;
			io_map[event_index] = io;
			event_index++;
		}

		/*
		 * If the generation number changes due to event addition
		 * or removal by a callback we restart the loop.
		 */
		curgen = io_tree.generation;

		for(DWORD event_offset = 0; event_offset < event_count;) {
			DWORD result = WSAWaitForMultipleEvents(event_count - event_offset, &events[event_offset], FALSE, timeout_ms, FALSE);

			if(result == WSA_WAIT_TIMEOUT) {
				break;
			}

			if(result < WSA_WAIT_EVENT_0 || result >= WSA_WAIT_EVENT_0 + event_count - event_offset) {
				return(false);
			}

			/* Look up io in the map by index. */
			event_index = result - WSA_WAIT_EVENT_0 + event_offset;
			io_t *io = io_map[event_index];

			if(io->fd == -1) {
				io->cb(io->data, 0);

				if(curgen != io_tree.generation) {
					break;
				}
			} else {
				WSANETWORKEVENTS network_events;

				if(WSAEnumNetworkEvents(io->fd, io->event, &network_events) != 0) {
					return(false);
				}

				if(network_events.lNetworkEvents & READ_EVENTS) {
					io->cb(io->data, IO_READ);

					if(curgen != io_tree.generation) {
						break;
					}
				}

				/*
				    The fd might be available for write too. However, if we already fired the read callback, that
				    callback might have deleted the io (e.g. through terminate_connection()), so we can't fire the
				    write callback here. Instead, we loop back and let the writable io loop above handle it.
				 */
			}

			/* Continue checking the rest of the events. */
			event_offset = event_index + 1;

			/* Just poll the next time through. */
			timeout_ms = 0;
		}
	}

#endif

	return true;
}

void event_exit(void) {
	running = false;
}
