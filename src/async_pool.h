#ifndef TINC_POOL_H
#define TINC_POOL_H

/*
    pool.h -- simple pool of buffers
    Copyright (C) 2018 Guus Sliepen <guus@tinc-vpn.org>,

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

#include "tinycthread.h"

typedef struct async_pool_t {
	thrd_t thrd;
	mtx_t mtx;
	cnd_t cnd;
	size_t nmemb;
	volatile bool active;
	size_t head;
	size_t tail;
	size_t ctail;
	void (*consume)(void *);
	void *bufs[0];
} async_pool_t;

async_pool_t *async_pool_alloc(size_t nmemb, size_t size, void (*consume)(void *));
void async_pool_free(async_pool_t *pool);
void *async_pool_get(async_pool_t *pool);
void async_pool_put(async_pool_t *pool, void *buf);

#endif
