/*
    ecdsa.c -- ECDSA key handling
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

#include "../logger.h"
#include "../ecdsa.h"
#include "../utils.h"
#include "../xalloc.h"

// Get and set ECDSA keys
//
ecdsa_t *ecdsa_set_base64_public_key(const char *p) {
	int len = strlen(p);

	if(len != 43) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Invalid size %d for public key!", len);
		return 0;
	}

	ecdsa_t *ecdsa = xzalloc(sizeof *ecdsa);
	len = b64decode(p, ecdsa->public, len);
	if(len != 32) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Invalid format of public key! len = %d", len);
		free(ecdsa);
		return 0;
	}

	return ecdsa;
}

char *ecdsa_get_base64_public_key(ecdsa_t *ecdsa) {
	char *base64 = xmalloc(44);
	b64encode(ecdsa->public, base64, sizeof ecdsa->public);

	return base64;
}

// Read PEM ECDSA keys

static bool read_pem(FILE *fp, const char *type, void *buf, size_t size) {
	char line[1024];
	bool data = false;
	size_t typelen = strlen(type);

	while(fgets(line, sizeof line, fp)) {
		if(!data) {
			if(strncmp(line, "-----BEGIN ", 11))
				continue;
			if(strncmp(line + 11, type, typelen))
				continue;
			data = true;
			continue;
		}

		if(!strncmp(line, "-----END ", 9))
			break;

		size_t linelen = strcspn(line, "\r\n");
		size_t len = b64decode(line, line, linelen);
		if(!len) {
			logger(DEBUG_ALWAYS, LOG_ERR, "Invalid base64 data in PEM file\n");
			return false;
		}

		if(len > size) {
			logger(DEBUG_ALWAYS, LOG_ERR, "Too much base64 data in PEM file\n");
			return false;
		}

		memcpy(buf, line, len);
		buf += len;
		size -= len;
	}

	if(size) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Too little base64 data in PEM file\n");
		return false;
	}

	return true;
}

ecdsa_t *ecdsa_read_pem_public_key(FILE *fp) {
	ecdsa_t *ecdsa = xzalloc(sizeof *ecdsa);
	if(read_pem(fp, "ED25519 PUBLIC KEY", ecdsa->public, sizeof ecdsa->public))
		return ecdsa;
	free(ecdsa);
	return 0;
}

ecdsa_t *ecdsa_read_pem_private_key(FILE *fp) {
	ecdsa_t *ecdsa = xmalloc(sizeof *ecdsa);
	if(read_pem(fp, "ED25519 PRIVATE KEY", ecdsa->private, sizeof *ecdsa))
		return ecdsa;
	free(ecdsa);
	return 0;
}

size_t ecdsa_size(ecdsa_t *ecdsa) {
	return 64;
}

// TODO: standardise output format?

bool ecdsa_sign(ecdsa_t *ecdsa, const void *in, size_t len, void *sig) {
	ed25519_sign(sig, in, len, ecdsa->public, ecdsa->private);
	return true;
}

bool ecdsa_verify(ecdsa_t *ecdsa, const void *in, size_t len, const void *sig) {
	return ed25519_verify(sig, in, len, ecdsa->public);
}

bool ecdsa_active(ecdsa_t *ecdsa) {
	return ecdsa;
}

void ecdsa_free(ecdsa_t *ecdsa) {
	free(ecdsa);
}
