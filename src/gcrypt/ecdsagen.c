/*
    ecdsagen.c -- ECDSA key generation and export
    Copyright (C) 2011-2013 Guus Sliepen <guus@tinc-vpn.org>

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

#include "../system.h"

#include "../ecdsagen.h"
#include "../utils.h"
#include "../xalloc.h"

// Generate ECDSA key

ecdsa_t *ecdsa_generate(void) {
	logger(DEBUG_ALWAYS, LOG_ERR, "EC support using libgcrypt not implemented");
	return NULL;
}

// Write PEM ECDSA keys

bool ecdsa_write_pem_public_key(ecdsa_t *ecdsa, FILE *fp) {
	return false;
}

bool ecdsa_write_pem_private_key(ecdsa_t *ecdsa, FILE *fp) {
	return false;
}
