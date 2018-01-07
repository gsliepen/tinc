/*
    async_send.c -- asynchronous send() functions
    Copyright (C) 2015 Guus Sliepen <guus@tinc-vpn.org>,

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
#include "net.h"

#include "async_send.h"

#include <assert.h>

#include "logger.h"
#include "tinycthread.h"
#include "utils.h"
#include "xalloc.h"
#include "netutl.h"

typedef struct async_send_request {
	int fd;
	void* buf;
	size_t len;
	int flags;
	sockaddr_t dest_addr;
} async_send_request_t;

bool async_send_enabled = false;
static thrd_t async_send_thrd;
static mtx_t async_send_mtx;
static cnd_t async_send_cnd;
static async_send_request_t* async_send_request = NULL;

static void async_send_sendrequest(const async_send_request_t* request) {
	assert(request);

	if (sendto(request->fd, request->buf, request->len, request->flags, &request->dest_addr.sa, SALEN(request->dest_addr.sa)) < 0 && !sockwouldblock(sockerrno)) {
		char* hostname = sockaddr2hostname(&request->dest_addr);
		logger(DEBUG_TRAFFIC, LOG_WARNING, "Error sending packet to %s: %s", hostname, sockstrerror(sockerrno));
		free(hostname);
	}
}

static int async_send_thread(void* data) {
	assert(mtx_lock(&async_send_mtx) == thrd_success);
	while (true) {
		while (async_send_enabled && !async_send_request) {
			assert(cnd_wait(&async_send_cnd, &async_send_mtx) == thrd_success);
		}

		if (async_send_request) {
			assert(mtx_unlock(&async_send_mtx) == thrd_success);

			async_send_sendrequest(async_send_request);
			free(async_send_request->buf);
			sockaddrfree(&async_send_request->dest_addr);
			free(async_send_request);

			assert(mtx_lock(&async_send_mtx) == thrd_success);
			async_send_request = NULL;
		}
		if (!async_send_enabled) break;
	}
	assert(mtx_unlock(&async_send_mtx) == thrd_success);
	return 0;
}

void async_sendto(int fd, const void* buf, size_t len, int flags, const sockaddr_t *dest_addr) {
	assert(async_send_enabled);

	assert(mtx_lock(&async_send_mtx) == thrd_success);

	if (!async_send_request) {
		async_send_request = xzalloc(sizeof(*async_send_request));
		async_send_request->fd = fd;
		async_send_request->buf = xmalloc(len);
		memcpy(async_send_request->buf, buf, len);
		async_send_request->len = len;
		async_send_request->flags = flags;
		sockaddrcpy(&async_send_request->dest_addr, dest_addr);

		assert(cnd_signal(&async_send_cnd) == thrd_success);
	}

	assert(mtx_unlock(&async_send_mtx) == thrd_success);
}

void async_send_init() {
	if (mtx_init(&async_send_mtx, mtx_plain) != thrd_success) {
		logger(DEBUG_ALWAYS, LOG_WARNING, "Unable to initialize async send mutex, falling back to synchronous mode");
		return;
	}
	if (cnd_init(&async_send_cnd) != thrd_success) {
		logger(DEBUG_ALWAYS, LOG_WARNING, "Unable to initialize async send condition variable, falling back to synchronous mode");
		mtx_destroy(&async_send_mtx);
		return;
	}

	async_send_enabled = true;

	if (thrd_create(&async_send_thrd, async_send_thread, NULL) != thrd_success) {
		logger(DEBUG_ALWAYS, LOG_WARNING, "Unable to initialize async send thread, falling back to synchronous mode");
		async_send_enabled = 0;
		cnd_destroy(&async_send_cnd);
		mtx_destroy(&async_send_mtx);
		return;
	}
}

void async_send_exit() {
	assert(mtx_lock(&async_send_mtx) == thrd_success);
	async_send_enabled = false;
	assert(cnd_broadcast(&async_send_cnd) == thrd_success);
	assert(mtx_unlock(&async_send_mtx) == thrd_success);

	int result = -1;
	assert(thrd_join(async_send_thrd, &result));
	assert(result == 0);

	mtx_destroy(&async_send_mtx);
}
