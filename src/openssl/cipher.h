/*
    cipher.h -- header file cipher.c
    Copyright (C) 2007-2012 Guus Sliepen <guus@tinc-vpn.org>

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

#ifndef __TINC_CIPHER_H__
#define __TINC_CIPHER_H__

#include <openssl/evp.h>

#define CIPHER_MAX_BLOCK_SIZE EVP_MAX_BLOCK_LENGTH
#define CIPHER_MAX_KEY_SIZE EVP_MAX_KEY_LENGTH
#define CIPHER_MAX_IV_SIZE EVP_MAX_IV_LENGTH

typedef struct cipher {
	EVP_CIPHER_CTX ctx;
	const EVP_CIPHER *cipher;
	struct cipher_counter *counter;
} cipher_t;

extern bool cipher_open_by_name(cipher_t *, const char *);
extern bool cipher_open_by_nid(cipher_t *, int);
extern bool cipher_open_blowfish_ofb(cipher_t *);
extern void cipher_close(cipher_t *);
extern size_t cipher_keylength(const cipher_t *);
extern bool cipher_set_key(cipher_t *, void *, bool);
extern bool cipher_set_key_from_rsa(cipher_t *, void *, size_t, bool);
extern bool cipher_set_counter(cipher_t *, const void *, size_t);
extern bool cipher_set_counter_key(cipher_t *, void *);
extern bool cipher_encrypt(cipher_t *, const void *indata, size_t inlen, void *outdata, size_t *outlen, bool);
extern bool cipher_decrypt(cipher_t *, const void *indata, size_t inlen, void *outdata, size_t *outlen, bool);
extern bool cipher_counter_xor(cipher_t *, const void *indata, size_t inlen, void *outdata);
extern int cipher_get_nid(const cipher_t *);
extern bool cipher_active(const cipher_t *);

#endif
