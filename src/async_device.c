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

#include "async_pool.h"
#include "logger.h"
#include "tinycthread.h"
#include "utils.h"
#include "xalloc.h"
#include "netutl.h"
#include "device.h"

#define ASYNC_DEVICE_QUEUE_LENGTH 128
static async_pool_t *vpn_packet_pool;

void async_device_write(vpn_packet_t *packet) {
	vpn_packet_t *copy = async_pool_get(vpn_packet_pool);
	memcpy(copy, packet, sizeof(*copy));
	async_pool_put(vpn_packet_pool, copy);
}

static void consumer(void *arg) {
	vpn_packet_t *packet = arg;
	devops.write(packet);
}

void async_device_init() {
	vpn_packet_pool = async_pool_alloc(ASYNC_DEVICE_QUEUE_LENGTH, sizeof(vpn_packet_t), consumer);
}

void async_device_exit() {
	async_pool_free(vpn_packet_pool);
}
