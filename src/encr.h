/*
    encr.h -- header for encr.c
    Copyright (C) 1998,1999,2000 Ivo Timmermans <zarq@iname.com>

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

    $Id: encr.h,v 1.3 2000/10/18 20:12:08 zarq Exp $
*/

#ifndef __TINC_ENCR_H__
#define __TINC_ENCR_H__

#include "net.h"

#define PRIVATE_KEY_BITS 128
#define PRIVATE_KEY_LENGTH (PRIVATE_KEY_BITS >> 3)

extern char *my_public_key_base36;
extern int my_key_expiry;

extern int security_init(void);

extern int send_portnumbers(int);
extern void set_shared_key(char *);
extern int send_passphrase(conn_list_t *);
extern int send_public_key(conn_list_t *);
extern int verify_passphrase(conn_list_t *, unsigned char *);
extern char *make_shared_key(char*);
extern void encrypt_passphrase(passphrase_t *pp);
extern void free_key(enc_key_t*);
extern void regenerate_keys(void);

#endif /* __TINC_ENCR_H__ */

