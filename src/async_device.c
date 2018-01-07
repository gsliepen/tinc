/*
    async_device.c -- asynchronous send() functions
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

#include "async_device.h"

#include <assert.h>

#include "logger.h"
#include "tinycthread.h"
#include "utils.h"
#include "xalloc.h"
#include "netutl.h"
#include "device.h"

bool async_device_enabled = false;
static thrd_t async_device_thrd;
static mtx_t async_device_mtx;
static cnd_t async_device_cnd;

#define ASYNC_DEVICE_QUEUE_LENGTH 128
vpn_packet_t async_device_queue[ASYNC_DEVICE_QUEUE_LENGTH];
size_t async_device_queue_index = 0;
size_t async_device_queue_length = 0;

static int async_device_thread(void* data) {
	assert(mtx_lock(&async_device_mtx) == thrd_success);
	while (true) {
		while (async_device_enabled && async_device_queue_length == 0) {
			assert(cnd_wait(&async_device_cnd, &async_device_mtx) == thrd_success);
		}

		if (async_device_queue_length > 0) {
			vpn_packet_t* request = &async_device_queue[async_device_queue_index];
			assert(mtx_unlock(&async_device_mtx) == thrd_success);

			devops.write(request);

			assert(mtx_lock(&async_device_mtx) == thrd_success);
			async_device_queue_index++;
			async_device_queue_index %= ASYNC_DEVICE_QUEUE_LENGTH;
			async_device_queue_length--;

			continue;
		}

		if (!async_device_enabled) break;
	}
	assert(mtx_unlock(&async_device_mtx) == thrd_success);
	return 0;
}

void async_device_write(vpn_packet_t *packet) {
	assert(async_device_enabled);

	assert(mtx_lock(&async_device_mtx) == thrd_success);

	if (async_device_queue_length < ASYNC_DEVICE_QUEUE_LENGTH) {
		vpn_packet_t* request = &async_device_queue[(async_device_queue_index + async_device_queue_length) % ASYNC_DEVICE_QUEUE_LENGTH];
		memcpy(request, packet, sizeof(*packet));

		if (async_device_queue_length == 0) {
			assert(cnd_signal(&async_device_cnd) == thrd_success);
		}

		async_device_queue_length++;
	}

	assert(mtx_unlock(&async_device_mtx) == thrd_success);
}

void async_device_init() {
	if (mtx_init(&async_device_mtx, mtx_plain) != thrd_success) {
		logger(DEBUG_ALWAYS, LOG_WARNING, "Unable to initialize async send mutex, falling back to synchronous mode");
		return;
	}
	if (cnd_init(&async_device_cnd) != thrd_success) {
		logger(DEBUG_ALWAYS, LOG_WARNING, "Unable to initialize async send condition variable, falling back to synchronous mode");
		mtx_destroy(&async_device_mtx);
		return;
	}

	async_device_enabled = true;

	if (thrd_create(&async_device_thrd, async_device_thread, NULL) != thrd_success) {
		logger(DEBUG_ALWAYS, LOG_WARNING, "Unable to initialize async send thread, falling back to synchronous mode");
		async_device_enabled = 0;
		cnd_destroy(&async_device_cnd);
		mtx_destroy(&async_device_mtx);
		return;
	}
}

void async_device_exit() {
	assert(mtx_lock(&async_device_mtx) == thrd_success);
	async_device_enabled = false;
	assert(cnd_broadcast(&async_device_cnd) == thrd_success);
	assert(mtx_unlock(&async_device_mtx) == thrd_success);

	int result = -1;
	assert(thrd_join(async_device_thrd, &result));
	assert(result == 0);

	mtx_destroy(&async_device_mtx);
}
