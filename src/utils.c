/*
    utils.c -- gathering of some stupid small functions
    Copyright (C) 1999-2005 Ivo Timmermans
                  2000-2013 Guus Sliepen <guus@tinc-vpn.org>

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

#include "system.h"

#include "../src/logger.h"
#include "utils.h"

static const char hexadecimals[] = "0123456789ABCDEF";
static const char base64_original[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static const char base64_urlsafe[] =  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
static const char base64_decode[256] = {
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 62, -1, 62, -1, 63,
	52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1, -1, -1, -1, -1, -1,
	-1,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
	15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, 63,
	-1, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
	41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
};

static int charhex2bin(char c) {
	if(isdigit(c))
		return c - '0';
	else
		return toupper(c) - 'A' + 10;
}

int hex2bin(const char *src, char *dst, int length) {
	int i;
	for(i = 0; i < length && isxdigit(src[i * 2]) && isxdigit(src[i * 2 + 1]); i++)
		dst[i] = charhex2bin(src[i * 2]) * 16 + charhex2bin(src[i * 2 + 1]);
	return i;
}

int bin2hex(const char *src, char *dst, int length) {
	for(int i = length - 1; i >= 0; i--) {
		dst[i * 2 + 1] = hexadecimals[(unsigned char) src[i] & 15];
		dst[i * 2] = hexadecimals[(unsigned char) src[i] >> 4];
	}
	dst[length * 2] = 0;
	return length * 2;
}

int b64decode(const char *src, char *dst, int length) {
	int i;
	uint32_t triplet = 0;
	unsigned char *udst = (unsigned char *)dst;

	for(i = 0; i < length / 3 * 4 && src[i]; i++) {
		triplet |= base64_decode[src[i] & 0xff] << (6 * (i & 3));
		if((i & 3) == 3) {
			if(triplet & 0xff000000U)
				return 0;
			udst[0] = triplet & 0xff; triplet >>= 8;
			udst[1] = triplet & 0xff; triplet >>= 8;
			udst[2] = triplet;
			triplet = 0;
			udst += 3;
		}
	}
	if(triplet & 0xff000000U)
		return 0;
	if((i & 3) == 3) {
		udst[0] = triplet & 0xff; triplet >>= 8;
		udst[1] = triplet & 0xff;
		return i / 4 * 3 + 2;
	} else if((i & 3) == 2) {
		udst[0] = triplet & 0xff;
		return i / 4 * 3 + 1;
	} else {
		return i / 4 * 3;
	}
}

static int b64encode_internal(const char *src, char *dst, int length, const char *alphabet) {
	uint32_t triplet;
	const unsigned char *usrc = (unsigned char *)src;
	int si = length / 3 * 3;
	int di = length / 3 * 4;

	switch(length % 3) {
		case 2:
			triplet = usrc[si] | usrc[si + 1] << 8;
			dst[di] = alphabet[triplet & 63]; triplet >>= 6;
			dst[di + 1] = alphabet[triplet & 63]; triplet >>= 6;
			dst[di + 2] = alphabet[triplet];
			dst[di + 3] = 0;
			length = di + 2;
			break;
		case 1:
			triplet = usrc[si];
			dst[di] = alphabet[triplet & 63]; triplet >>= 6;
			dst[di + 1] = alphabet[triplet];
			dst[di + 2] = 0;
			length = di + 1;
			break;
		default:
			dst[di] = 0;
			length = di;
			break;
	}

	while(si > 0) {
		di -= 4;
		si -= 3;
		triplet = usrc[si] | usrc[si + 1] << 8 | usrc[si + 2] << 16;
		dst[di] = alphabet[triplet & 63]; triplet >>= 6;
		dst[di + 1] = alphabet[triplet & 63]; triplet >>= 6;
		dst[di + 2] = alphabet[triplet & 63]; triplet >>= 6;
		dst[di + 3] = alphabet[triplet];
	}

	return length;
}

int b64encode(const char *src, char *dst, int length) {
	return b64encode_internal(src, dst, length, base64_original);
}

int b64encode_urlsafe(const char *src, char *dst, int length) {
	return b64encode_internal(src, dst, length, base64_urlsafe);
}

#if defined(HAVE_MINGW) || defined(HAVE_CYGWIN)
#ifdef HAVE_CYGWIN
#include <w32api/windows.h>
#endif

const char *winerror(int err) {
	static char buf[1024], *ptr;

	ptr = buf + sprintf(buf, "(%d) ", err);

	if (!FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL, err, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), ptr, sizeof(buf) - (ptr - buf), NULL)) {
		strncpy(buf, "(unable to format errormessage)", sizeof(buf));
	};

	if((ptr = strchr(buf, '\r')))
		*ptr = '\0';

	return buf;
}
#endif

unsigned int bitfield_to_int(const void *bitfield, size_t size) {
	unsigned int value = 0;
	if(size > sizeof value)
		size = sizeof value;
	memcpy(&value, bitfield, size);
	return value;
}
