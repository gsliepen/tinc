/*
    event.h -- I/O, timeout and signal event handling
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

#ifndef __TINC_EVENT_H__
#define __TINC_EVENT_H__

#include "splay_tree.h"

#define IO_READ 1
#define IO_WRITE 2

typedef void (*io_cb_t)(void *data, int flags);
typedef void (*timeout_cb_t)(void *data);
typedef void (*signal_cb_t)(void *data);

typedef struct io_t {
	int fd;
	int flags;
	io_cb_t cb;
	void *data;
	splay_node_t node;
} io_t;

typedef struct timeout_t {
	struct timeval tv;
	timeout_cb_t cb;
	void *data;
	splay_node_t node;
} timeout_t;

typedef struct signal_t {
	int signum;
	signal_cb_t cb;
	void *data;
	splay_node_t node;
} signal_t;

extern struct timeval now;

extern void io_add(io_t *io, io_cb_t cb, void *data, int fd, int flags);
extern void io_del(io_t *io);
extern void io_set(io_t *io, int flags);

extern void timeout_add(timeout_t *timeout, timeout_cb_t cb, void *data, struct timeval *tv);
extern void timeout_del(timeout_t *timeout);
extern void timeout_set(timeout_t *timeout, struct timeval *tv);

extern void signal_add(signal_t *sig, signal_cb_t cb, void *data, int signum);
extern void signal_del(signal_t *sig);

extern bool event_loop(void);
extern void event_flush_output(void);
extern void event_exit(void);

#endif
