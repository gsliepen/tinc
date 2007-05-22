/*
    cipher.h -- header file cipher.c
    Copyright (C) 2007 Guus Sliepen <guus@tinc-vpn.org>

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.

    $Id$
*/

#ifndef __TINC_CIPHER_H__
#define __TINC_CIPHER_H__

#include <gcrypt.h>

typedef struct cipher {
	gcry_cipher_hd_t handle;
	char *key;
	int nid;
	uint16_t keylen;
	uint16_t blklen;
} cipher_t;

bool cipher_open_by_name(struct cipher *, const char *);
bool cipher_open_by_nid(struct cipher *, int);
bool cipher_open_blowfish_ofb(struct cipher *);
void cipher_close(struct cipher *);
bool cipher_regenerate_key(struct cipher *);
bool cipher_encrypt(struct cipher *, void *indata, size_t inlen, void *outdata, size_t *outlen);
bool cipher_decrypt(struct cipher *, void *indata, size_t inlen, void *outdata, size_t *outlen);
int cipher_get_nid(struct cipher *);

#endif
