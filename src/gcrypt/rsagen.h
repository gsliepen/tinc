/*
    rsagen.h -- RSA key generation and export
    Copyright (C) 2008 Guus Sliepen <guus@tinc-vpn.org>

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

#ifndef __TINC_RSAGEN_H__
#define __TINC_RSAGEN_H__

#include "rsa.h"

extern bool rsa_generate(rsa_t *rsa, size_t bits, unsigned long exponent);
extern bool rsa_write_pem_public_key(rsa_t *rsa, FILE *fp);
extern bool rsa_write_pem_private_key(rsa_t *rsa, FILE *fp);

#endif
