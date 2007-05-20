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

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.

    $Id$
*/

#ifndef __TINC_RSA_H__
#define __TINC_RSA_H__

#include <gcrypt.h>

typedef struct rsa_key_t {
	gcry_mpi_t n;
	gcry_mpi_t e;
	gcry_mpi_t d;
} rsa_key_t;

extern bool read_pem_rsa_public_key(FILE *fp, struct rsa_key_t *key);
extern bool read_pem_rsa_private_key(FILE *fp, struct rsa_key_t *key);
extern unsigned int get_rsa_size(struct rsa_key_t *key);
extern bool rsa_public_encrypt(size_t len, void *in, void *out, struct rsa_key_t *key);
extern bool rsa_private_decrypt(size_t len, void *in, void *out, struct rsa_key_t *key);


#endif
