/*
    event.c -- event support for Windows
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

#include <assert.h>

#include "../event.h"
#include "../utils.h"
#include "../net.h"

static bool running = false;
static DWORD event_count = 0;

static const long READ_EVENTS = FD_READ | FD_ACCEPT | FD_CLOSE;
static const long WRITE_EVENTS = FD_WRITE | FD_CONNECT;

void io_add(io_t *io, io_cb_t cb, void *data, int fd, int flags) {
	if(io->cb) {
		return;
	}

	io->fd = fd;

	if(io->fd != -1) {
		io->event = WSACreateEvent();

		if(io->event == WSA_INVALID_EVENT) {
			abort();
		}
	}

	event_count++;

	io->cb = cb;
	io->data = data;
	io->node.data = io;

	io_set(io, flags);

	if(!splay_insert_node(&io_tree, &io->node)) {
		abort();
	}
}

void io_add_event(io_t *io, io_cb_t cb, void *data, WSAEVENT event) {
	io->event = event;
	io_add(io, cb, data, -1, 0);
}

void io_set(io_t *io, int flags) {
	if(flags == io->flags) {
		return;
	}

	io->flags = flags;

	if(io->fd == -1) {
		return;
	}

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
}

void io_del(io_t *io) {
	if(!io->cb) {
		return;
	}

	io_set(io, 0);

	if(io->fd != -1 && WSACloseEvent(io->event) == FALSE) {
		abort();
	}

	event_count--;
	splay_unlink_node(&io_tree, &io->node);
	io->cb = NULL;
}

bool event_loop(void) {
	running = true;

	assert(WSA_WAIT_EVENT_0 == 0);

	while(running) {
		struct timeval diff;
		struct timeval *tv = timeout_execute(&diff);
		DWORD timeout_ms = tv ? (DWORD)(tv->tv_sec * 1000 + tv->tv_usec / 1000 + 1) : WSA_INFINITE;

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

			if(result >= event_count - event_offset) {
				return false;
			}

			/* Look up io in the map by index. */
			event_index = result + event_offset;
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

	return true;
}

void event_exit(void) {
	running = false;
}
