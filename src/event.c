/*
    event.c -- I/O, timeout, and event handling
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

struct timeval now;

static int io_compare(const io_t *a, const io_t *b) {
#ifndef HAVE_WINDOWS
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

	uintptr_t ap = (uintptr_t)a;
	uintptr_t bp = (uintptr_t)b;

	if(ap < bp) {
		return -1;
	}

	if(ap > bp) {
		return 1;
	}

	return 0;
}

splay_tree_t io_tree = {.compare = (splay_compare_t)io_compare};
splay_tree_t timeout_tree = {.compare = (splay_compare_t)timeout_compare};

void timeout_add(timeout_t *timeout, timeout_cb_t cb, void *data, const struct timeval *tv) {
	timeout->cb = cb;
	timeout->data = data;
	timeout->node.data = timeout;

	timeout_set(timeout, tv);
}

void timeout_set(timeout_t *timeout, const struct timeval *tv) {
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

struct timeval *timeout_execute(struct timeval *diff) {
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
