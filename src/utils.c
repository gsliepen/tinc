/*
    utils.c -- gathering of some stupid small functions
    Copyright (C) 1999-2005 Ivo Timmermans
                  2000-2009 Guus Sliepen <guus@tinc-vpn.org>

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
static const char base64imals[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static int charhex2bin(char c) {
	if(isdigit(c))
		return c - '0';
	else
		return toupper(c) - 'A' + 10;
}

static int charb64decode(char c) {
	if(c >= 'a')
		return c - 'a' + 26;
	else if(c >= 'A')
		return c - 'A';
	else if(c >= '0') 
		return c - '0' + 52;
	else if(c == '+')
		return 62;
	else
		return 63;
}

int hex2bin(const char *src, char *dst, int length) {
	int i;
	for(i = 0; i < length && src[i * 2] && src[i * 2 + 1]; i++)
		dst[i] = charhex2bin(src[i * 2]) * 16 + charhex2bin(src[i * 2 + 1]);
	return i;
}

int bin2hex(const char *src, char *dst, int length) {
	int i;
	for(i = length - 1; i >= 0; i--) {
		dst[i * 2 + 1] = hexadecimals[(unsigned char) src[i] & 15];
		dst[i * 2] = hexadecimals[(unsigned char) src[i] >> 4];
	}
	dst[length * 2] = 0;
	return length * 2;
}

int b64decode(const char *src, char *dst, int length) {
	int i;
	uint32_t triplet = 0;
	unsigned char *udst = dst;

	for(i = 0; i < length / 3 * 4 && src[i]; i++) {
		triplet |= charb64decode(src[i]) << (6 * (i & 3));
		if((i & 3) == 3) {
			udst[0] = triplet & 0xff; triplet >>= 8;
			udst[1] = triplet & 0xff; triplet >>= 8;
			udst[2] = triplet;
			triplet = 0;
			udst += 3;
		}
	}
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

int b64encode(const char *src, char *dst, int length) {
	uint32_t triplet;
	const unsigned char *usrc = src;
	int si = length / 3 * 3;
	int di = length / 3 * 4;

	switch(length % 3) {
		case 2:	
			triplet = usrc[si] | usrc[si + 1] << 8;
			dst[di] = base64imals[triplet & 63]; triplet >>= 6;
			dst[di + 1] = base64imals[triplet & 63]; triplet >>= 6;
			dst[di + 2] = base64imals[triplet];
			dst[di + 3] = 0;
			length = di + 2;
			break;
		case 1:
			triplet = usrc[si];
			dst[di] = base64imals[triplet & 63]; triplet >>= 6;
			dst[di + 1] = base64imals[triplet];
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
		dst[di] = base64imals[triplet & 63]; triplet >>= 6;
		dst[di + 1] = base64imals[triplet & 63]; triplet >>= 6;
		dst[di + 2] = base64imals[triplet & 63]; triplet >>= 6;
		dst[di + 3] = base64imals[triplet];
	}

	return length;
}

#if defined(HAVE_MINGW) || defined(HAVE_CYGWIN)
#ifdef HAVE_CYGWIN
#include <w32api/windows.h>
#endif

const char *winerror(int err) {
	static char buf[1024], *newline;

	if (!FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
	        NULL, err, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), buf, sizeof(buf), NULL)) {
		strncpy(buf, "(unable to format errormessage)", sizeof(buf));
	};

	if((newline = strchr(buf, '\r')))
		*newline = '\0';

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
