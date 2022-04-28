#ifndef TINC_GCRYPT_RSA_H
#define TINC_GCRYPT_RSA_H

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

#include <gcrypt.h>

#include "../rsa.h"
#include "../xalloc.h"

#define TINC_RSA_INTERNAL
typedef struct rsa {
	gcry_mpi_t n;
	gcry_mpi_t e;
	gcry_mpi_t d;
} rsa_t;

extern rsa_t *rsa_new(void) ATTR_MALLOC ATTR_DEALLOCATOR(rsa_free);

#endif
