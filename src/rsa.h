#ifndef TINC_RSA_H
#define TINC_RSA_H

/*
    rsa.h -- RSA key handling
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

#ifndef TINC_RSA_INTERNAL
typedef struct rsa rsa_t;
#endif

extern void rsa_free(rsa_t *rsa);
extern rsa_t *rsa_set_hex_public_key(const char *n, const char *e) ATTR_MALLOC ATTR_DEALLOCATOR(rsa_free);
extern rsa_t *rsa_set_hex_private_key(const char *n, const char *e, const char *d) ATTR_MALLOC ATTR_DEALLOCATOR(rsa_free);
extern rsa_t *rsa_read_pem_public_key(FILE *fp) ATTR_MALLOC ATTR_DEALLOCATOR(rsa_free);
extern rsa_t *rsa_read_pem_private_key(FILE *fp) ATTR_MALLOC ATTR_DEALLOCATOR(rsa_free);
extern size_t rsa_size(const rsa_t *rsa);
extern bool rsa_public_encrypt(rsa_t *rsa, const void *in, size_t len, void *out) ATTR_WARN_UNUSED;
extern bool rsa_private_decrypt(rsa_t *rsa, const void *in, size_t len, void *out) ATTR_WARN_UNUSED;

#endif
