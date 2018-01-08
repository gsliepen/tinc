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

#include "async_pool.h"
#include "logger.h"
#include "tinycthread.h"
#include "utils.h"
#include "xalloc.h"
#include "netutl.h"

typedef struct async_send_request {
	int fd;
	size_t len;
	int flags;
	sockaddr_t dest_addr;
	uint8_t buf[MAXSIZE];
} async_send_request_t;

#define ASYNC_SEND_QUEUE_LENGTH 128
async_pool_t *send_pool;

static void async_send_sendrequest(void *arg) {
	async_send_request_t *request = arg;

	if (sendto(request->fd, request->buf, request->len, request->flags, &request->dest_addr.sa, SALEN(request->dest_addr.sa)) < 0 && !sockwouldblock(sockerrno)) {
		char* hostname = sockaddr2hostname(&request->dest_addr);
		logger(DEBUG_TRAFFIC, LOG_WARNING, "Error sending packet to %s: %s", hostname, sockstrerror(sockerrno));
		free(hostname);
	}
}

void async_sendto(int fd, const void* buf, size_t len, int flags, const sockaddr_t *dest_addr) {
	async_send_request_t* request = async_pool_get(send_pool);

	request->fd = fd;
	memcpy(request->buf, buf, len);
	request->len = len;
	request->flags = flags;
	sockaddrcpy(&request->dest_addr, dest_addr);

	async_pool_put(send_pool, request);
}

void async_send_init() {
	send_pool = async_pool_alloc(ASYNC_SEND_QUEUE_LENGTH, sizeof(async_send_request_t), async_send_sendrequest);
}

void async_send_exit() {
	async_pool_free(send_pool);
}
