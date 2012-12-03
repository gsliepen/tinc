/*
    event.c -- I/O, timeout and signal event handling
    Copyright (C) 2012 Guus Sliepen <guus@tinc-vpn.org>

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

struct timeval now;

static fd_set readfds;
static fd_set writefds;
static volatile bool running;

static int io_compare(const io_t *a, const io_t *b) {
	return a->fd - b->fd;
}

static int timeout_compare(const timeout_t *a, const timeout_t *b) {
	struct timeval diff;
	timersub(&a->tv, &b->tv, &diff);
	if(diff.tv_sec < 0)
		return -1;
	if(diff.tv_sec > 0)
		return 1;
	if(diff.tv_usec < 0)
		return -1;
	if(diff.tv_usec > 0)
		return 1;
	if(a < b)
		return -1;
	if(a > b)
		return 1;
	return 0;
}

static int signal_compare(const signal_t *a, const signal_t *b) {
	return a->signum - b->signum;
}

static splay_tree_t io_tree = {.compare = (splay_compare_t)io_compare};
static splay_tree_t timeout_tree = {.compare = (splay_compare_t)timeout_compare};
static splay_tree_t signal_tree = {.compare = (splay_compare_t)signal_compare};

void io_add(io_t *io, io_cb_t cb, void *data, int fd, int flags) {
	if(io->cb)
		return;

	io->fd = fd;
	io->cb = cb;
	io->data = data;
	io->node.data = io;

	io_set(io, flags);

	if(!splay_insert_node(&io_tree, &io->node))
		abort();
}

void io_set(io_t *io, int flags) {
	io->flags = flags;

	if(flags & IO_READ)
		FD_SET(io->fd, &readfds);
	else
		FD_CLR(io->fd, &readfds);

	if(flags & IO_WRITE)
		FD_SET(io->fd, &writefds);
	else
		FD_CLR(io->fd, &writefds);
}

void io_del(io_t *io) {
	if(!io->cb)
		return;

	io_set(io, 0);

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
	if(timerisset(&timeout->tv))
		splay_unlink_node(&timeout_tree, &timeout->node);

	if(!now.tv_sec)
		gettimeofday(&now, NULL);

	timeradd(&now, tv, &timeout->tv);

	if(!splay_insert_node(&timeout_tree, &timeout->node))
		abort();
}

void timeout_del(timeout_t *timeout) {
	if(!timeout->cb)
		return;

	splay_unlink_node(&timeout_tree, &timeout->node);
	timeout->cb = 0;
	timeout->tv = (struct timeval){0, 0};
}

#ifndef HAVE_MINGW
static io_t signalio;
static int pipefd[2] = {-1, -1};

static void signal_handler(int signum) {
	unsigned char num = signum;
	write(pipefd[1], &num, 1);
}

static void signalio_handler(void *data, int flags) {
	unsigned char signum;
	if(read(pipefd[0], &signum, 1) != 1)
		return;

	signal_t *sig = splay_search(&signal_tree, &((signal_t){.signum = signum}));
	if(sig)
		sig->cb(sig->data);
}

static void pipe_init(void) {
	if(!pipe(pipefd))
		io_add(&signalio, signalio_handler, NULL, pipefd[0], IO_READ);
}

void signal_add(signal_t *sig, signal_cb_t cb, void *data, int signum) {
	if(sig->cb)
		return;

	sig->cb = cb;
	sig->data = data;
	sig->signum = signum;
	sig->node.data = sig;

	if(pipefd[0] == -1)
		pipe_init();

	signal(sig->signum, signal_handler);

	if(!splay_insert_node(&signal_tree, &sig->node))
		abort();
}

void signal_del(signal_t *sig) {
	if(!sig->cb)
		return;

	signal(sig->signum, SIG_DFL);

	splay_unlink_node(&signal_tree, &sig->node);
	sig->cb = NULL;
}
#endif

bool event_loop(void) {
	running = true;

	fd_set readable;
	fd_set writable;

	while(running) {
		gettimeofday(&now, NULL);
		struct timeval diff, *tv = NULL;

		while(timeout_tree.head) {
			timeout_t *timeout = timeout_tree.head->data;
			timersub(&timeout->tv, &now, &diff);

			if(diff.tv_sec < 0) {
				timeout->cb(timeout->data);
				if(timercmp(&timeout->tv, &now, <))
					timeout_del(timeout);
			} else {
				tv = &diff;
				break;
			}
		}

		memcpy(&readable, &readfds, sizeof readable);
		memcpy(&writable, &writefds, sizeof writable);

		int fds = 0;

		if(io_tree.tail) {
			io_t *last = io_tree.tail->data;
			fds = last->fd + 1;
		}

#ifdef HAVE_MINGW
		LeaveCriticalSection(&mutex);
#endif
		int n = select(fds, &readable, &writable, NULL, tv);
#ifdef HAVE_MINGW
		EnterCriticalSection(&mutex);
#endif

		if(n < 0) {
			if(sockwouldblock(errno))
				continue;
			else
				return false;
		}

		if(!n)
			continue;

		for splay_each(io_t, io, &io_tree) {
			if(FD_ISSET(io->fd, &writable))
				io->cb(io->data, IO_WRITE);
			else if(FD_ISSET(io->fd, &readable))
				io->cb(io->data, IO_READ);
		}
	}

	return true;
}

void event_exit(void) {
	running = false;
}
