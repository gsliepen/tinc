/*
    cipher.c -- wrapper functions for encryption algorithms
    Copyright (C) 1999 Ivo Timmermans <zarq@iname.com>

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

#include "config.h"

#include <dlfcn.h>
#include <string.h>
#include <syslog.h>

#include <cipher.h>

#include "blowfish/blowfish.h"
#include "idea/idea.h"

#include "net.h"

void (*blowfish_cfb64_encrypt) (unsigned char*, unsigned char*, int,
				BF_KEY*, unsigned char*, int*, int) = NULL;
void (*blowfish_set_key) (BF_KEY*, int, char*) = NULL;

unsigned char initvec[] = { 0x22, 0x7b, 0xad, 0x55, 0x41, 0xf4, 0x3e, 0xf3 };
BF_KEY encryption_key;

void low_crypt_key(unsigned char *in, unsigned char *out, BF_KEY *k, long len, int c)
{
  int count = 7;
  unsigned char ivec[8];

  memcpy(ivec, initvec, 8);

  blowfish_cfb64_encrypt(in, out, len, k, &ivec[0], &count, c);
}

void do_encrypt(vpn_packet_t *in, real_packet_t *out, enc_key_t *key)
{
  unsigned char ivec[8];
  int r;

  memcpy(ivec, initvec, 8);
  cipher_set_key(&encryption_key, key->length, key->key);
  low_crypt_key((char*)(&in->data), (char*)(&out->data.data),
		   &encryption_key, in->len, BF_ENCRYPT);
  
  out->len = in->len + 2;
  r = (in->len + 2) % 8;
  if(r)
    out->len += (8-r);
  out->len += 8;
  /* The smallest multiple of 8 greater
     than or equal to in->len + 8 */

  out->data.len = in->len;
}

void do_decrypt(real_packet_t *in, vpn_packet_t *out, enc_key_t *key)
{
  unsigned char ivec[8];

  memcpy(ivec, initvec, 8);
  cipher_set_key(&encryption_key, key->length, key->key);
  low_crypt_key((char*)(&in->data.data), (char*)(&out->data),
		   &encryption_key, in->data.len, BF_DECRYPT);
  out->len = in->data.len;
}

void cipher_set_key(BF_KEY *k, int l, char *t)
{
  blowfish_set_key(k, l, t);
}

int cipher_init(int which)
{
  void *dlhandle;
  char *error;

  if((dlhandle = dlopen(PKGLIBDIR "libblowfish.so.0", RTLD_LAZY)) == NULL)
    {
      syslog(LOG_ERR, "%s: %m", PKGLIBDIR "libblowfish.so.0");
      return -1;
    }

  blowfish_cfb64_encrypt = dlsym(dlhandle, "BF_cfb64_encrypt");
  if((error = dlerror()) != NULL)
    {
      syslog(LOG_ERR, "%s", error);
      return -1;
    }
  blowfish_set_key = dlsym(dlhandle, "BF_set_key");

  return 0;
}
