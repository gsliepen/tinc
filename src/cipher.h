#ifndef TINC_CIPHER_H
#define TINC_CIPHER_H

/*
    cipher.h -- header file cipher.c
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

#include "system.h"

#define CIPHER_MAX_BLOCK_SIZE 32
#define CIPHER_MAX_IV_SIZE 16
#define CIPHER_MAX_KEY_SIZE 32

#ifndef DISABLE_LEGACY

#ifdef HAVE_OPENSSL
#include "openssl/cipher.h"
#elif HAVE_LIBGCRYPT
#include "gcrypt/cipher.h"
#else
#error Incorrect cryptographic library, please reconfigure.
#endif

extern void cipher_free(cipher_t *cipher);
extern cipher_t *cipher_alloc(void) ATTR_MALLOC ATTR_DEALLOCATOR(cipher_free);
extern bool cipher_open_by_name(cipher_t *cipher, const char *name);
extern bool cipher_open_by_nid(cipher_t *cipher, nid_t nid);
extern void cipher_close(cipher_t *cipher);
extern size_t cipher_keylength(const cipher_t *cipher);
extern size_t cipher_blocksize(const cipher_t *cipher);
extern uint64_t cipher_budget(const cipher_t *cipher);
extern bool cipher_set_key(cipher_t *cipher, void *key, bool encrypt) ATTR_WARN_UNUSED;
extern bool cipher_set_key_from_rsa(cipher_t *cipher, void *rsa, size_t len, bool encrypt) ATTR_WARN_UNUSED;
extern bool cipher_encrypt(cipher_t *cipher, const void *indata, size_t inlen, void *outdata, size_t *outlen, bool oneshot) ATTR_WARN_UNUSED;
extern bool cipher_decrypt(cipher_t *cipher, const void *indata, size_t inlen, void *outdata, size_t *outlen, bool oneshot) ATTR_WARN_UNUSED;
extern nid_t cipher_get_nid(const cipher_t *cipher);
extern bool cipher_active(const cipher_t *cipher);

#endif // DISABLE_LEGACY

#endif // TINC_CIPHER_H
