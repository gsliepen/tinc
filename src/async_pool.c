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

// 1 2 3 4 5 6 7 8 9
//     |   |   |
//     |   |   \-> head
//     |   \-> tail
//     \-> ctail (consume tail)

static bool no_free_buffers(async_pool_t *pool) {
	return (pool->head + 1) % pool->nmemb == pool->ctail;
}

static bool nothing_to_consume(async_pool_t *pool) {
	return pool->ctail == pool->tail;
}

static int async_pool_thread(void *arg) {
	async_pool_t *pool = arg;
	assert(mtx_lock(&pool->mtx) == thrd_success);

	while(true) {
		while(pool->active && nothing_to_consume(pool)) {
			cnd_wait(&pool->cnd, &pool->mtx);
		}

		if(!pool->active) {
			break;
		}

		assert(pool->bufs[pool->ctail]);
		pool->consume(pool->bufs[pool->ctail++]);
		pool->ctail %= pool->nmemb;
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
	if (pool->consume)
		thrd_create(&pool->thrd, async_pool_thread, pool);
	return pool;
}

void async_pool_free(async_pool_t *pool) {
	if(!pool) {
		return;
	}

	if (pool->consume) {
		assert(mtx_lock(&pool->mtx) == thrd_success);
		pool->active = false;
		cnd_signal(&pool->cnd);
		cnd_wait(&pool->cnd, &pool->mtx);
	}

	for(size_t i = 0; i < pool->nmemb; i++) {
		assert(pool->bufs[i]);
		free(pool->bufs[i]);
	}

	assert(mtx_unlock(&pool->mtx) == thrd_success);
	free(pool);
}

void *async_pool_get(async_pool_t *pool) {
	assert(mtx_lock(&pool->mtx) == thrd_success);

	while(no_free_buffers(pool)) {
		cnd_wait(&pool->cnd, &pool->mtx);
	}

	void *buf = pool->bufs[pool->head];
	pool->bufs[pool->head++] = NULL;
	pool->head %= pool->nmemb;

	assert(mtx_unlock(&pool->mtx) == thrd_success);
	return buf;
}

void async_pool_put(async_pool_t *pool, void *buf) {
	assert(buf);
	assert(mtx_lock(&pool->mtx) == thrd_success);

	assert(!pool->bufs[pool->tail]);
	pool->bufs[pool->tail++] = buf;
	pool->tail %= pool->nmemb;
	cnd_signal(&pool->cnd);

	assert(mtx_unlock(&pool->mtx) == thrd_success);
}

void *async_pool_ctail(async_pool_t *pool) {
	void *buf = NULL;
	assert(mtx_lock(&pool->mtx) == thrd_success);
	if (!nothing_to_consume(pool))
		buf = pool->bufs[pool->ctail];
	assert(mtx_unlock(&pool->mtx) == thrd_success);
	return buf;
}

void async_pool_consume(async_pool_t *pool, void *buf) {
	assert(mtx_lock(&pool->mtx) == thrd_success);
	assert(!nothing_to_consume(pool) && pool->bufs[pool->ctail] == buf);
	pool->ctail++;
	pool->ctail %= pool->nmemb;
	assert(mtx_unlock(&pool->mtx) == thrd_success);
}
