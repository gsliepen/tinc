/*
    crypto.c -- Cryptographic miscellaneous functions and initialisation
    Copyright (C) 2007-2021 Guus Sliepen <guus@tinc-vpn.org>

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

#include <openssl/rand.h>
#include <openssl/engine.h>

#include "../crypto.h"

void crypto_init(void) {
#if OPENSSL_VERSION_MAJOR < 3
	ENGINE_load_builtin_engines();
#endif

	if(!RAND_status()) {
		fprintf(stderr, "Not enough entropy for the PRNG!\n");
		abort();
	}
}
