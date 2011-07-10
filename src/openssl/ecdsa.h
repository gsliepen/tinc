/*
    ecdsa.h -- ECDSA key handling
    Copyright (C) 2011 Guus Sliepen <guus@tinc-vpn.org>

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

#ifndef __TINC_ECDSA_H__
#define __TINC_ECDSA_H__

#include <openssl/ec.h>

typedef EC_KEY *ecdsa_t;

extern bool ecdsa_set_base64_public_key(ecdsa_t *ecdsa, const char *p);
extern char *ecdsa_get_base64_public_key(ecdsa_t *ecdsa);
extern bool ecdsa_read_pem_public_key(ecdsa_t *ecdsa, FILE *fp);
extern bool ecdsa_read_pem_private_key(ecdsa_t *ecdsa, FILE *fp);
extern size_t ecdsa_size(ecdsa_t *ecdsa);
extern bool ecdsa_sign(ecdsa_t *ecdsa, const void *in, size_t inlen, void *out);
extern bool ecdsa_verify(ecdsa_t *ecdsa, const void *in, size_t inlen, const void *out);
extern bool ecdsa_active(ecdsa_t *ecdsa);
extern void ecdsa_free(ecdsa_t *ecdsa);

#endif
