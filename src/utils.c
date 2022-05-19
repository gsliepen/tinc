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

#include "logger.h"
#include "system.h"
#include "utils.h"
#include "xalloc.h"

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

static uint8_t charhex2bin(char c) {
	uint8_t cu = (uint8_t) c;

	if(isdigit(cu)) {
		return cu - '0';
	} else {
		return toupper(cu) - 'A' + 10;
	}
}

size_t hex2bin(const char *src, void *vdst, size_t length) {
	uint8_t *dst = vdst;
	size_t i;

	for(i = 0; i < length && isxdigit((uint8_t) src[i * 2]) && isxdigit((uint8_t) src[i * 2 + 1]); i++) {
		dst[i] = charhex2bin(src[i * 2]) * 16 + charhex2bin(src[i * 2 + 1]);
	}

	return i;
}

size_t bin2hex(const void *vsrc, char *dst, size_t length) {
	const char *src = vsrc;

	for(size_t i = length; i > 0;) {
		--i;
		dst[i * 2 + 1] = hexadecimals[(unsigned char) src[i] & 15];
		dst[i * 2] = hexadecimals[(unsigned char) src[i] >> 4];
	}

	dst[length * 2] = 0;
	return length * 2;
}

size_t b64decode_tinc(const char *src, void *dst, size_t length) {
	size_t i;
	uint32_t triplet = 0;
	unsigned char *udst = (unsigned char *)dst;

	for(i = 0; i < length && src[i]; i++) {
		triplet |= (uint32_t)(base64_decode[src[i] & 0xff] << (6 * (i & 3)));

		if((i & 3) == 3) {
			if(triplet & 0xff000000U) {
				return 0;
			}

			udst[0] = triplet & 0xff;
			triplet >>= 8;
			udst[1] = triplet & 0xff;
			triplet >>= 8;
			udst[2] = triplet;
			triplet = 0;
			udst += 3;
		}
	}

	if(triplet & 0xff000000U) {
		return 0;
	}

	if((i & 3) == 3) {
		udst[0] = triplet & 0xff;
		triplet >>= 8;
		udst[1] = triplet & 0xff;
		return i / 4 * 3 + 2;
	} else if((i & 3) == 2) {
		udst[0] = triplet & 0xff;
		return i / 4 * 3 + 1;
	} else {
		return i / 4 * 3;
	}
}

bool is_decimal(const char *str) {
	if(!str) {
		return false;
	}

	errno = 0;
	char *badchar = NULL;
	strtol(str, &badchar, 10);
	return !errno && badchar != str && !*badchar;
}

// itoa() conflicts with a similarly named function under MinGW.
char *int_to_str(int num) {
	char *str = NULL;
	xasprintf(&str, "%d", num);
	return str;
}

static size_t b64encode_tinc_internal(const void *src, char *dst, size_t length, const char *alphabet) {
	uint32_t triplet;
	const unsigned char *usrc = (unsigned char *)src;
	size_t si = length / 3 * 3;
	size_t di = length / 3 * 4;

	switch(length % 3) {
	case 2:
		triplet = usrc[si] | usrc[si + 1] << 8;
		dst[di] = alphabet[triplet & 63];
		triplet >>= 6;
		dst[di + 1] = alphabet[triplet & 63];
		triplet >>= 6;
		dst[di + 2] = alphabet[triplet];
		dst[di + 3] = 0;
		length = di + 3;
		break;

	case 1:
		triplet = usrc[si];
		dst[di] = alphabet[triplet & 63];
		triplet >>= 6;
		dst[di + 1] = alphabet[triplet];
		dst[di + 2] = 0;
		length = di + 2;
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
		dst[di] = alphabet[triplet & 63];
		triplet >>= 6;
		dst[di + 1] = alphabet[triplet & 63];
		triplet >>= 6;
		dst[di + 2] = alphabet[triplet & 63];
		triplet >>= 6;
		dst[di + 3] = alphabet[triplet];
	}

	return length;
}

size_t b64encode_tinc(const void *src, char *dst, size_t length) {
	return b64encode_tinc_internal(src, dst, length, base64_original);
}

size_t b64encode_tinc_urlsafe(const void *src, char *dst, size_t length) {
	return b64encode_tinc_internal(src, dst, length, base64_urlsafe);
}

#ifdef HAVE_WINDOWS
const char *winerror(int err) {
	static char buf[1024], *ptr;

	ptr = buf + snprintf(buf, sizeof(buf), "(%d) ", err);

	if(!FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
	                  NULL, err, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), ptr, sizeof(buf) - (ptr - buf), NULL)) {
		strncpy(buf, "(unable to format errormessage)", sizeof(buf));
	};

	if((ptr = strchr(buf, '\r'))) {
		*ptr = '\0';
	}

	return buf;
}
#endif

bool check_id(const char *id) {
	if(!id || !*id) {
		return false;
	}

	for(; *id; id++)
		if(!isalnum((uint8_t) *id) && *id != '_') {
			return false;
		}

	return true;
}

bool check_netname(const char *netname, bool strict) {
	if(!netname || !*netname || *netname == '.') {
		return false;
	}

	for(const char *c = netname; *c; c++) {
		if(iscntrl((uint8_t) *c)) {
			return false;
		}

		if(*c == '/' || *c == '\\') {
			return false;
		}

		if(strict && strchr(" $%<>:`\"|?*", *c)) {
			return false;
		}
	}

	return true;
}

/* Windows doesn't define HOST_NAME_MAX. */
#ifndef HOST_NAME_MAX
#define HOST_NAME_MAX 255
#endif

char *replace_name(const char *name) {
	char *ret_name;

	if(name[0] == '$') {
		char *envname = getenv(name + 1);
		char hostname[HOST_NAME_MAX + 1];

		if(!envname) {
			if(strcmp(name + 1, "HOST")) {
				logger(DEBUG_ALWAYS, LOG_ERR, "Invalid Name: environment variable %s does not exist\n", name + 1);
				return NULL;
			}

			if(gethostname(hostname, sizeof(hostname)) || !*hostname) {
				logger(DEBUG_ALWAYS, LOG_ERR, "Could not get hostname: %s\n", sockstrerror(sockerrno));
				return NULL;
			}

			hostname[HOST_NAME_MAX] = 0;
			envname = hostname;
		}

		ret_name = xstrdup(envname);

		for(char *c = ret_name; *c; c++)
			if(!isalnum((uint8_t) *c)) {
				*c = '_';
			}
	} else {
		ret_name = xstrdup(name);
	}

	if(!check_id(ret_name)) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Invalid name for myself!");
		free(ret_name);
		return NULL;
	}

	return ret_name;
}

bool string_eq(const char *first, const char *second) {
	return !first == !second &&
	       !(first && second && strcmp(first, second));
}
