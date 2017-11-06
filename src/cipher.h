#ifndef TINC_CIPHER_H
#define TINC_CIPHER_H

/*
    cipher.h -- header file cipher.c
    Copyright (C) 2007-2016 Guus Sliepen <guus@tinc-vpn.org>

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

#define CIPHER_MAX_BLOCK_SIZE 32
#define CIPHER_MAX_IV_SIZE 16
#define CIPHER_MAX_KEY_SIZE 32

#ifndef DISABLE_LEGACY

typedef struct cipher cipher_t;

extern cipher_t *cipher_open_by_name(const char *name) __attribute__((__malloc__));
extern cipher_t *cipher_open_by_nid(int nid) __attribute__((__malloc__));
extern void cipher_close(cipher_t *cipher);
extern size_t cipher_keylength(const cipher_t *cipher);
extern size_t cipher_blocksize(const cipher_t *cipher);
extern uint64_t cipher_budget(const cipher_t *cipher);
extern bool cipher_set_key(cipher_t *cipher, void *key, bool encrypt) __attribute__((__warn_unused_result__));
extern bool cipher_set_key_from_rsa(cipher_t *cipher, void *rsa, size_t len, bool encrypt) __attribute__((__warn_unused_result__));
extern bool cipher_encrypt(cipher_t *cipher, const void *indata, size_t inlen, void *outdata, size_t *outlen, bool oneshot) __attribute__((__warn_unused_result__));
extern bool cipher_decrypt(cipher_t *cipher, const void *indata, size_t inlen, void *outdata, size_t *outlen, bool oneshot) __attribute__((__warn_unused_result__));
extern int cipher_get_nid(const cipher_t *cipher);
extern bool cipher_active(const cipher_t *cipher);

#endif

#endif
