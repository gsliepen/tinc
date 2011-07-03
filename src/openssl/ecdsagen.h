/*
    ecdsagen.h -- ECDSA key generation and export
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

#ifndef __TINC_ECDSAGEN_H__
#define __TINC_ECDSAGEN_H__

#include "ecdsa.h"

extern bool ecdsa_generate(ecdsa_t *ecdsa);
extern bool ecdsa_write_pem_public_key(ecdsa_t *ecdsa, FILE *fp);
extern bool ecdsa_write_pem_private_key(ecdsa_t *ecdsa, FILE *fp);
extern char *ecdsa_get_base64_public_key(ecdsa_t *ecdsa);

#endif
