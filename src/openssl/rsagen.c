/*
    rsagen.c -- RSA key generation and export
    Copyright (C) 2008-2013 Guus Sliepen <guus@tinc-vpn.org>

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

#include <openssl/pem.h>
#include <openssl/err.h>

#define __TINC_RSA_INTERNAL__
typedef RSA rsa_t;

#include "../logger.h"
#include "../rsagen.h"

/* This function prettyprints the key generation process */

static void indicator(int a, int b, void *p) {
	switch (a) {
		case 0:
			fprintf(stderr, ".");
			break;

		case 1:
			fprintf(stderr, "+");
			break;

		case 2:
			fprintf(stderr, "-");
			break;

		case 3:
			switch (b) {
				case 0:
					fprintf(stderr, " p\n");
					break;

				case 1:
					fprintf(stderr, " q\n");
					break;

				default:
					fprintf(stderr, "?");
			}
			break;

		default:
			fprintf(stderr, "?");
	}
}

// Generate RSA key

rsa_t *rsa_generate(size_t bits, unsigned long exponent) {
	return RSA_generate_key(bits, exponent, indicator, NULL);
}

// Write PEM RSA keys

bool rsa_write_pem_public_key(rsa_t *rsa, FILE *fp) {
	return PEM_write_RSAPublicKey(fp, rsa);
}

bool rsa_write_pem_private_key(rsa_t *rsa, FILE *fp) {
	return PEM_write_RSAPrivateKey(fp, rsa, NULL, NULL, 0, NULL, NULL);
}
