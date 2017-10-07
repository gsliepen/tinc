/*
    ecdh.c -- Diffie-Hellman key exchange handling
    Copyright (C) 2011-2013 Guus Sliepen <guus@tinc-vpn.org>

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

#include "../system.h"

#include "ed25519.h"

#define TINC_ECDH_INTERNAL
typedef struct ecdh_t {
	uint8_t private[64];
} ecdh_t;

#include "../crypto.h"
#include "../ecdh.h"
#include "../xalloc.h"

ecdh_t *ecdh_generate_public(void *pubkey) {
	ecdh_t *ecdh = xzalloc(sizeof(*ecdh));

	uint8_t seed[32];
	randomize(seed, sizeof(seed));
	ed25519_create_keypair(pubkey, ecdh->private, seed);

	return ecdh;
}

bool ecdh_compute_shared(ecdh_t *ecdh, const void *pubkey, void *shared) {
	ed25519_key_exchange(shared, pubkey, ecdh->private);
	free(ecdh);
	return true;
}

void ecdh_free(ecdh_t *ecdh) {
	free(ecdh);
}
