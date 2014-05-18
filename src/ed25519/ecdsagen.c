/*
    ecdsagen.c -- ECDSA key generation and export
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

#define __TINC_ECDSA_INTERNAL__
typedef struct {
	uint8_t private[64];
	uint8_t public[32];
} ecdsa_t;

#include "../crypto.h"
#include "../ecdsagen.h"
#include "../utils.h"
#include "../xalloc.h"

// Generate ECDSA key

ecdsa_t *ecdsa_generate(void) {
	ecdsa_t *ecdsa = xzalloc(sizeof *ecdsa);

	uint8_t seed[32];
	randomize(seed, sizeof seed);
	ed25519_create_keypair(ecdsa->public, ecdsa->private, seed);

	return ecdsa;
}

// Write PEM ECDSA keys

static bool write_pem(FILE *fp, const char *type, void *buf, size_t size) {
	fprintf(fp, "-----BEGIN %s-----\n", type);

	char base64[65];
	while(size) {
		size_t todo = size > 48 ? 48 : size;
		b64encode(buf, base64, todo);
		fprintf(fp, "%s\n", base64);
		buf += todo;
		size -= todo;
	}

	fprintf(fp, "-----END %s-----\n", type);
	return !ferror(fp);
}

bool ecdsa_write_pem_public_key(ecdsa_t *ecdsa, FILE *fp) {
	return write_pem(fp, "ED25519 PUBLIC KEY", ecdsa->public, sizeof ecdsa->public);
}

bool ecdsa_write_pem_private_key(ecdsa_t *ecdsa, FILE *fp) {
	return write_pem(fp, "ED25519 PRIVATE KEY", ecdsa->private, sizeof *ecdsa);
}
