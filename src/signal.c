/*
    signal.c -- signal handling
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

// From Matz's Ruby
#ifndef NSIG
# define NSIG (_SIGMAX + 1)      /* For QNX */
#endif

static io_t signalio;
static int pipefd[2] = {-1, -1};
static signal_t *signal_handle[NSIG + 1] = {NULL};

static void signal_handler(int signum) {
	unsigned char num = signum;

	if(write(pipefd[1], &num, 1) != 1) {
		// Pipe full or broken, nothing we can do about it.
	}
}

static void signalio_handler(void *data, int flags) {
	(void)data;
	(void)flags;
	unsigned char signum;

	if(read(pipefd[0], &signum, 1) != 1) {
		return;
	}

	signal_t *sig = signal_handle[signum];

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

	sig->signum = signum;
	sig->cb = cb;
	sig->data = data;

	if(pipefd[0] == -1) {
		pipe_init();
	}

	signal(signum, signal_handler);

	signal_handle[signum] = sig;
}

void signal_del(signal_t *sig) {
	if(!sig->cb) {
		return;
	}

	signal(sig->signum, SIG_DFL);

	signal_handle[sig->signum] = NULL;
	sig->cb = NULL;
}
