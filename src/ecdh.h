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

#define ECDH_SIZE 32
#define ECDH_SHARED_SIZE 32

#ifndef TINC_ECDH_INTERNAL
typedef struct ecdh ecdh_t;
#endif

extern ecdh_t *ecdh_generate_public(void *pubkey) __attribute__((__malloc__));
extern bool ecdh_compute_shared(ecdh_t *ecdh, const void *pubkey, void *shared) __attribute__((__warn_unused_result__));
extern void ecdh_free(ecdh_t *ecdh);

#endif
