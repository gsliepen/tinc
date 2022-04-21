/*
    prf.c -- Pseudo-Random Function for key material generation
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

#include <openssl/obj_mac.h>

#include "digest.h"
#include "../digest.h"
#include "../prf.h"

/* Generate key material from a master secret and a seed, based on RFC 4346 section 5.
   We use SHA512 instead of MD5 and SHA1.
 */

static bool prf_xor(nid_t nid, const uint8_t *secret, size_t secretlen, uint8_t *seed, size_t seedlen, uint8_t *out, size_t outlen) {
	digest_t digest = {0};

	if(!digest_open_by_nid(&digest, nid, DIGEST_ALGO_SIZE)) {
		digest_close(&digest);
		return false;
	}

	if(!digest_set_key(&digest, secret, secretlen)) {
		digest_close(&digest);
		return false;
	}

	size_t len = digest_length(&digest);

	/* Data is what the "inner" HMAC function processes.
	   It consists of the previous HMAC result plus the seed.
	 */

	char *data = alloca(len + seedlen);
	memset(data, 0, len);
	memcpy(data + len, seed, seedlen);

	uint8_t *hash = alloca(len);

	while(outlen > 0) {
		/* Inner HMAC */
		if(!digest_create(&digest, data, len + seedlen, data)) {
			digest_close(&digest);
			return false;
		}

		/* Outer HMAC */
		if(!digest_create(&digest, data, len + seedlen, hash)) {
			digest_close(&digest);
			return false;
		}

		/* XOR the results of the outer HMAC into the out buffer */
		size_t i;

		for(i = 0; i < len && i < outlen; i++) {
			*out++ ^= hash[i];
		}

		outlen -= i;
	}

	digest_close(&digest);
	return true;
}

bool prf(const uint8_t *secret, size_t secretlen, uint8_t *seed, size_t seedlen, uint8_t *out, size_t outlen) {
	/* This construction allows us to easily switch back to a scheme where the PRF is calculated using two different digest algorithms. */
	memset(out, 0, outlen);

	return prf_xor(NID_sha512, secret, secretlen, seed, seedlen, out, outlen);
}
