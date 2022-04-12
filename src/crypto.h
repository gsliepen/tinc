#ifndef TINC_CRYPTO_H
#define TINC_CRYPTO_H

#include "system.h"

/*
    crypto.h -- header for crypto.c
    Copyright (C) 2007-2013 Guus Sliepen <guus@tinc-vpn.org>

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

extern void crypto_init(void);
extern uint64_t xoshiro(void);
extern void prng_init(void);
extern void prng_randomize(void *buf, size_t buflen);

static inline uint32_t prng(uint32_t limit) {
	uint64_t bins = UINT64_MAX / limit;
	uint64_t reject_after = bins * limit;
	uint64_t value;

	do {
		value = xoshiro();
	} while(value >= reject_after);

	return value / bins;
}

#endif
