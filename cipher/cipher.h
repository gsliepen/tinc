/*
    cipher.c -- header file for cipher.c
    Copyright (C) 1999,2000 Ivo Timmermans <zarq@iname.com>

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
*/

#ifndef __TINC_CIPHER_H__
#define __TINC_CIPHER_H__

#include "blowfish/blowfish.h"
#include "net.h"

enum {
  CIPHER_BLOWFISH = 1,
  CIPHER_IDEA
};

extern BF_KEY encryption_key;

void low_crypt_key(unsigned char*, unsigned char*, BF_KEY*, long, int);

void do_encrypt(vpn_packet_t *in, real_packet_t *out, enc_key_t *);
void do_decrypt(real_packet_t *in, vpn_packet_t *out, enc_key_t *);

void cipher_set_key(BF_KEY*, int, char*);
int cipher_init(int);

#endif /* __TINC_CIPHER_H__ */
