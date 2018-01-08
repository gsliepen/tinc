/*
    pool.c -- simple pool of buffers
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

#include "system.h"

#include <assert.h>

#include "async_pool.h"
#include "xalloc.h"

static int async_pool_thread(void *arg) {
	async_pool_t *pool = arg;
	assert(mtx_lock(&pool->mtx) == thrd_success);

	while(true) {
		while(pool->active && (pool->tail == pool->head || !pool->bufs[pool->tail])) {
			cnd_wait(&pool->cnd, &pool->mtx);
		}

		if(!pool->active) {
			break;
		}

		if(pool->tail == pool->head) {
			continue;
		}

		pool->consume(pool->bufs[pool->tail++]);
		pool->tail %= pool->nmemb;
		cnd_signal(&pool->cnd);
	}

	cnd_signal(&pool->cnd);
	assert(mtx_unlock(&pool->mtx) == thrd_success);
	return 0;
}


async_pool_t *async_pool_alloc(size_t nmemb, size_t size, void (*consume)(void *)) {
	async_pool_t *pool = xzalloc(sizeof(*pool) + nmemb * sizeof(void *));

	for(size_t i = 0; i < nmemb; i++) {
		pool->bufs[i] = xmalloc(size);
	}

	pool->nmemb = nmemb;
	pool->active = true;
	pool->consume = consume;
	thrd_create(&pool->thrd, async_pool_thread, pool);
	return pool;
}

void async_pool_free(async_pool_t *pool) {
	if(!pool) {
		return;
	}

	assert(mtx_lock(&pool->mtx) == thrd_success);
	pool->active = false;
	cnd_broadcast(&pool->cnd);
	cnd_wait(&pool->cnd, &pool->mtx);

	for(size_t i = 0; i < pool->nmemb; i++) {
		assert(pool->bufs[i]);
		free(pool->bufs[i]);
	}

	assert(mtx_unlock(&pool->mtx) == thrd_success);
	free(pool);
}

void *async_pool_get(async_pool_t *pool) {
	void *buf;
	assert(mtx_lock(&pool->mtx) == thrd_success);

	while(!(buf = pool->bufs[pool->head])) {
		cnd_wait(&pool->cnd, &pool->mtx);
	}

	pool->bufs[pool->head++] = NULL;
	pool->head %= pool->nmemb;

	assert(mtx_unlock(&pool->mtx) == thrd_success);
	return buf;
}

void async_pool_put(async_pool_t *pool, void *buf) {
	assert(mtx_lock(&pool->mtx) == thrd_success);

	assert(pool->bufs[pool->tail] == NULL);
	pool->bufs[pool->tail] = buf;
	cnd_signal(&pool->cnd);

	assert(mtx_unlock(&pool->mtx) == thrd_success);
}
