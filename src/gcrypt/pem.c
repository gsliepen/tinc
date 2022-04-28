/*
    pem.c -- PEM encoding and decoding
    Copyright (C) 2007-2022 Guus Sliepen <guus@tinc-vpn.org>

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

#include "pem.h"
#include "../utils.h"

// Base64 decoding table

static const uint8_t b64dec[128] = {
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0x3e, 0xff, 0xff, 0xff, 0x3f,
	0x34, 0x35, 0x36, 0x37, 0x38, 0x39,
	0x3a, 0x3b, 0x3c, 0x3d, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0x00,
	0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
	0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
	0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12,
	0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
	0x19, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
	0x1f, 0x20, 0x21, 0x22, 0x23, 0x24,
	0x25, 0x26, 0x27, 0x28, 0x29, 0x2a,
	0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30,
	0x31, 0x32, 0x33, 0xff, 0xff, 0xff,
	0xff, 0xff
};

static const char b64enc[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                             "abcdefghijklmnopqrstuvwxyz"
                             "0123456789+/";

// Heavily based on code by Jouni Malinen <j@w1.fi>
// https://web.mit.edu/freebsd/head/contrib/wpa/src/utils/base64.c
static size_t b64encode(char *dst, const void *src, const size_t length) {
	const uint8_t *end = (const uint8_t *)src + length;
	const uint8_t *in = src;
	char *pos = dst;

	while(end - in >= 3) {
		*pos++ = b64enc[in[0] >> 2];
		*pos++ = b64enc[((in[0] & 0x03) << 4) | (in[1] >> 4)];
		*pos++ = b64enc[((in[1] & 0x0f) << 2) | (in[2] >> 6)];
		*pos++ = b64enc[in[2] & 0x3f];
		in += 3;
	}

	if(end - in) {
		*pos++ = b64enc[in[0] >> 2];

		if(end - in == 1) {
			*pos++ = b64enc[(in[0] & 0x03) << 4];
			*pos++ = '=';
		} else {
			*pos++ = b64enc[((in[0] & 0x03) << 4) | (in[1] >> 4)];
			*pos++ = b64enc[(in[1] & 0x0f) << 2];
		}

		*pos++ = '=';
	}

	*pos = '\0';

	return pos - dst;
}


bool pem_encode(FILE *fp, const char *header, uint8_t *buf, size_t size) {
	if(fprintf(fp, "-----BEGIN %s-----\n", header) <= 0) {
		return false;
	}

	char *b64 = alloca(B64_SIZE(size));
	const size_t b64len = b64encode(b64, buf, size);

	for(size_t i = 0; i < b64len; i += 64) {
		if(fprintf(fp, "%.64s\n", &b64[i]) <= 0) {
			return false;
		}
	}

	return fprintf(fp, "-----END %s-----\n", header) > 0;
}

bool pem_decode(FILE *fp, const char *header, uint8_t *buf, size_t size, size_t *outsize) {
	bool decode = false;
	char line[1024];
	uint16_t word = 0;
	int shift = 10;
	size_t i, j = 0;

	while(!feof(fp)) {
		if(!fgets(line, sizeof(line), fp)) {
			return false;
		}

		if(!decode && !strncmp(line, "-----BEGIN ", 11)) {
			if(!strncmp(line + 11, header, strlen(header))) {
				decode = true;
			}

			continue;
		}

		if(decode && !strncmp(line, "-----END", 8)) {
			break;
		}

		if(!decode) {
			continue;
		}

		for(i = 0; line[i] >= ' '; i++) {
			if((signed char)line[i] < 0 || b64dec[(int)line[i]] == 0xff) {
				break;
			}

			word |= b64dec[(int)line[i]] << shift;
			shift -= 6;

			if(shift <= 2) {
				if(j > size) {
					errno = ENOMEM;
					return false;
				}

				buf[j++] = word >> 8;
				word = (uint16_t)(word << 8);
				shift += 8;
			}
		}
	}

	if(outsize) {
		*outsize = j;
	}

	return true;
}
