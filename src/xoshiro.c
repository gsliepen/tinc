/*  Written in 2018 by David Blackman and Sebastiano Vigna (vigna@acm.org)

To the extent possible under law, the author has dedicated all copyright
and related and neighboring rights to this software to the public domain
worldwide. This software is distributed without any warranty.

See <http://creativecommons.org/publicdomain/zero/1.0/>. */

#include "system.h"

#include "crypto.h"
#include "random.h"

/* This is xoshiro256** 1.0, one of our all-purpose, rock-solid
   generators. It has excellent (sub-ns) speed, a state (256 bits) that is
   large enough for any parallel application, and it passes all tests we
   are aware of.

   For generating just floating-point numbers, xoshiro256+ is even faster.

   The state must be seeded so that it is not everywhere zero. If you have
   a 64-bit seed, we suggest to seed a splitmix64 generator and use its
   output to fill s. */

static inline uint64_t rotl(const uint64_t x, int k) {
	return (x << k) | (x >> (64 - k));
}

static uint64_t s[4];

uint64_t xoshiro(void) {
	const uint64_t result = rotl(s[1] * 5, 7) * 9;

	const uint64_t t = s[1] << 17;

	s[2] ^= s[0];
	s[3] ^= s[1];
	s[1] ^= s[2];
	s[0] ^= s[3];

	s[2] ^= t;

	s[3] = rotl(s[3], 45);

	return result;
}

void prng_init(void) {
	do {
		randomize(s, sizeof(s));
	} while(!s[0] && !s[1] && !s[2] && !s[3]);
}

void prng_randomize(void *buf, size_t buflen) {
	uint8_t *p = buf;
	uint64_t value;

	while(buflen > sizeof(value)) {
		value = xoshiro();
		memcpy(p, &value, sizeof(value));
		p += sizeof(value);
		buflen -= sizeof(value);
	}

	if(!buflen) {
		return;
	}

	value = xoshiro();
	memcpy(p, &value, buflen);
}
