#ifndef TINC_ECDH_H
#define TINC_ECDH_H

/*
    ecdh.h -- header file for ecdh.c
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

#include "system.h"

#define ECDH_SIZE 32
#define ECDH_SHARED_SIZE 32

#ifndef TINC_ECDH_INTERNAL
typedef struct ecdh ecdh_t;
#endif

extern void ecdh_free(ecdh_t *ecdh);
extern ecdh_t *ecdh_generate_public(void *pubkey) ATTR_MALLOC ATTR_DEALLOCATOR(ecdh_free);
extern bool ecdh_compute_shared(ecdh_t *ecdh, const void *pubkey, void *shared) ATTR_WARN_UNUSED;

#endif
