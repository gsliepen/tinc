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

#include <openssl/err.h>
#include <openssl/ec.h>
#include <openssl/ecdh.h>
#include <openssl/obj_mac.h>

#define __TINC_ECDH_INTERNAL__
typedef EC_KEY ecdh_t;

#include "../ecdh.h"
#include "../logger.h"
#include "../utils.h"
#include "../xalloc.h"

ecdh_t *ecdh_generate_public(void *pubkey) {
	ecdh_t *ecdh = EC_KEY_new_by_curve_name(NID_secp521r1);
	if(!ecdh) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Generating EC key_by_curve_name failed: %s", ERR_error_string(ERR_get_error(), NULL));
		return false;
	}

	if(!EC_KEY_generate_key(ecdh)) {
		EC_KEY_free(ecdh);
		logger(DEBUG_ALWAYS, LOG_ERR, "Generating EC key failed: %s", ERR_error_string(ERR_get_error(), NULL));
		return NULL;
	}

	const EC_POINT *point = EC_KEY_get0_public_key(ecdh);
	if(!point) {
		EC_KEY_free(ecdh);
		logger(DEBUG_ALWAYS, LOG_ERR, "Getting public key failed: %s", ERR_error_string(ERR_get_error(), NULL));
		return NULL;
	}

	size_t result = EC_POINT_point2oct(EC_KEY_get0_group(ecdh), point, POINT_CONVERSION_COMPRESSED, pubkey, ECDH_SIZE, NULL);
	if(!result) {
		EC_KEY_free(ecdh);
		logger(DEBUG_ALWAYS, LOG_ERR, "Converting EC_POINT to binary failed: %s", ERR_error_string(ERR_get_error(), NULL));
		return NULL;
	}

	return ecdh;
}

bool ecdh_compute_shared(ecdh_t *ecdh, const void *pubkey, void *shared) {
	EC_POINT *point = EC_POINT_new(EC_KEY_get0_group(ecdh));
	if(!point) {
		logger(DEBUG_ALWAYS, LOG_ERR, "EC_POINT_new() failed: %s", ERR_error_string(ERR_get_error(), NULL));
		EC_KEY_free(ecdh);
		return false;
	}

	int result = EC_POINT_oct2point(EC_KEY_get0_group(ecdh), point, pubkey, ECDH_SIZE, NULL);
	if(!result) {
		EC_POINT_free(point);
		EC_KEY_free(ecdh);
		logger(DEBUG_ALWAYS, LOG_ERR, "Converting binary to EC_POINT failed: %s", ERR_error_string(ERR_get_error(), NULL));
		return false;
	}

	result = ECDH_compute_key(shared, ECDH_SIZE, point, ecdh, NULL);
	EC_POINT_free(point);
	EC_KEY_free(ecdh);

	if(!result) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Computing Elliptic Curve Diffie-Hellman shared key failed: %s", ERR_error_string(ERR_get_error(), NULL));
		return false;
	}

	return true;
}

void ecdh_free(ecdh_t *ecdh) {
	if(ecdh)
		EC_KEY_free(ecdh);
}
