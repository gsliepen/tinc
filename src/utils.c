/*
    utils.c -- gathering of some stupid small functions
    Copyright (C) 1999-2005 Ivo Timmermans
                  2000-2014 Guus Sliepen <guus@tinc-vpn.org>

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

static int charhex2bin(char c) {
	if(isdigit(c)) {
		return c - '0';
	} else {
		return toupper(c) - 'A' + 10;
	}
}

bool hex2bin(char *src, char *dst, int length) {
	for(int i = 0; i < length; i++) {
		if(!isxdigit(src[i * 2]) || !isxdigit(src[i * 2 + 1])) {
			return false;
		}

		dst[i] = charhex2bin(src[i * 2]) * 16 + charhex2bin(src[i * 2 + 1]);
	}

	return true;
}

void bin2hex(char *src, char *dst, int length) {
	int i;

	for(i = length - 1; i >= 0; i--) {
		dst[i * 2 + 1] = hexadecimals[(unsigned char) src[i] & 15];
		dst[i * 2] = hexadecimals[(unsigned char) src[i] >> 4];
	}
}

#if defined(HAVE_MINGW) || defined(HAVE___CYGWIN32__)
#ifdef HAVE___CYGWIN32__
#include <w32api/windows.h>
#endif

const char *winerror(int err) {
	static char buf[1024], *ptr;

	ptr = buf + sprintf(buf, "(%d) ", err);

	if(!FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
	                  NULL, err, MAKELANGID(LANG_NEUTRAL, SUBLANG_NEUTRAL), ptr, sizeof(buf) - (ptr - buf), NULL)) {
		strcpy(ptr, "(unable to format errormessage)");
	};

	if((ptr = strchr(buf, '\r'))) {
		*ptr = '\0';
	}

	return buf;
}
#endif

unsigned int bitfield_to_int(const void *bitfield, size_t size) {
	unsigned int value = 0;

	if(size > sizeof(value)) {
		size = sizeof(value);
	}

	memcpy(&value, bitfield, size);
	return value;
}

/**
 * As memcmp(), but constant-time.
 * Returns 0 when data is equal, non-zero otherwise.
 */
int memcmp_constant_time(const void *a, const void *b, size_t size) {
	const uint8_t *a1 = a, *b1 = b;
	int ret = 0;
	size_t i;

	for(i = 0; i < size; i++) {
		ret |= *a1++ ^ *b1++;
	}

	return ret;
}
