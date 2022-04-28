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

#include "../prf.h"
#include "../ed25519/sha512.h"

static void memxor(uint8_t *buf, uint8_t c, size_t len) {
	for(size_t i = 0; i < len; i++) {
		buf[i] ^= c;
	}
}

static const size_t mdlen = 64;
static const size_t blklen = 128;

static bool hmac_sha512(const uint8_t *key, size_t keylen, const uint8_t *msg, size_t msglen, uint8_t *out) {
	const size_t tmplen = blklen + mdlen;
	uint8_t *tmp = alloca(tmplen);

	sha512_context md;

	if(keylen <= blklen) {
		memcpy(tmp, key, keylen);
		memset(tmp + keylen, 0, blklen - keylen);
	} else {
		if(sha512(key, keylen, tmp) != 0) {
			return false;
		}

		memset(tmp + mdlen, 0, blklen - mdlen);
	}

	if(sha512_init(&md) != 0) {
		return false;
	}

	// ipad
	memxor(tmp, 0x36, blklen);

	if(sha512_update(&md, tmp, blklen) != 0) {
		return false;
	}

	// message
	if(sha512_update(&md, msg, msglen) != 0) {
		return false;
	}

	if(sha512_final(&md, tmp + blklen) != 0) {
		return false;
	}

	// opad
	memxor(tmp, 0x36 ^ 0x5c, blklen);

	if(sha512(tmp, tmplen, out) != 0) {
		return false;
	}

	return true;
}


/* Generate key material from a master secret and a seed, based on RFC 4346 section 5.
   We use SHA512 instead of MD5 and SHA1.
 */

bool prf(const uint8_t *secret, size_t secretlen, uint8_t *seed, size_t seedlen, uint8_t *out, size_t outlen) {
	/* Data is what the "inner" HMAC function processes.
	   It consists of the previous HMAC result plus the seed.
	 */

	const size_t datalen = mdlen + seedlen;
	uint8_t *data = alloca(datalen);

	memset(data, 0, mdlen);
	memcpy(data + mdlen, seed, seedlen);

	uint8_t *hash = alloca(mdlen);

	while(outlen > 0) {
		/* Inner HMAC */
		if(!hmac_sha512(secret, secretlen, data, datalen, data)) {
			return false;
		}

		/* Outer HMAC */
		if(outlen >= mdlen) {
			if(!hmac_sha512(secret, secretlen, data, datalen, out)) {
				return false;
			}

			out += mdlen;
			outlen -= mdlen;
		} else {
			if(!hmac_sha512(secret, secretlen, data, datalen, hash)) {
				return false;
			}

			memcpy(out, hash, outlen);
			out += outlen;
			outlen = 0;
		}
	}

	return true;
}
