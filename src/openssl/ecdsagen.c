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

#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/obj_mac.h>

#define __TINC_ECDSA_INTERNAL__
typedef EC_KEY ecdsa_t;

#include "../ecdsagen.h"
#include "../utils.h"
#include "../xalloc.h"

// Generate ECDSA key

ecdsa_t *ecdsa_generate(void) {
	ecdsa_t *ecdsa = EC_KEY_new_by_curve_name(NID_secp521r1);

	if(!ecdsa || !EC_KEY_generate_key(ecdsa)) {
		fprintf(stderr, "Generating EC key failed: %s", ERR_error_string(ERR_get_error(), NULL));
		ecdsa_free(ecdsa);
		return false;
	}

	EC_KEY_set_asn1_flag(ecdsa, OPENSSL_EC_NAMED_CURVE);
	EC_KEY_set_conv_form(ecdsa, POINT_CONVERSION_COMPRESSED);

	return ecdsa;
}

// Write PEM ECDSA keys

bool ecdsa_write_pem_public_key(ecdsa_t *ecdsa, FILE *fp) {
	BIO *out = BIO_new(BIO_s_file());
	if(!out)
		return false;
	BIO_set_fp(out, fp, BIO_NOCLOSE);
	bool result = PEM_write_bio_EC_PUBKEY(out, ecdsa);
	BIO_free(out);
	return result;
}

bool ecdsa_write_pem_private_key(ecdsa_t *ecdsa, FILE *fp) {
	BIO *out = BIO_new(BIO_s_file());
	if(!out)
		return false;
	BIO_set_fp(out, fp, BIO_NOCLOSE);
	bool result = PEM_write_bio_ECPrivateKey(out, ecdsa, NULL, NULL, 0, NULL, NULL);
	BIO_free(out);
	return result;
}
