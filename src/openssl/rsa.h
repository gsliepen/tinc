/*
    rsa.h -- RSA key handling
    Copyright (C) 2007 Guus Sliepen <guus@tinc-vpn.org>

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

#ifndef __TINC_RSA_H__
#define __TINC_RSA_H__

#include <openssl/rsa.h>

typedef RSA *rsa_t;

extern bool rsa_set_hex_public_key(rsa_t *rsa, char *n, char *e);
extern bool rsa_set_hex_private_key(rsa_t *rsa, char *n, char *e, char *d);
extern bool rsa_read_pem_public_key(rsa_t *rsa, FILE *fp);
extern bool rsa_read_pem_private_key(rsa_t *rsa, FILE *fp);
extern size_t rsa_size(rsa_t *rsa);
extern bool rsa_public_encrypt(rsa_t *rsa, void *in, size_t inlen, void *out);
extern bool rsa_private_decrypt(rsa_t *rsa, void *in, size_t inlen, void *out);
extern bool rsa_active(rsa_t *rsa);
extern void rsa_free(rsa_t *rsa);


#endif
