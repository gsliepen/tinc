/*
    encr.c -- everything that deals with encryption
    Copyright (C) 1998,99 Ivo Timmermans <zarq@iname.com>

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

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <sys/socket.h>
#include <sys/time.h>

#ifdef HAVE_GMP_H
# include <gmp.h>
#else
# ifdef HAVE_GMP2_GMP_H
#  include <gmp2/gmp.h>
# endif
#endif

#include <utils.h>
#include <xalloc.h>

#include <cipher.h>

#include "conf.h"
#include "encr.h"
#include "net.h"
#include "protocol.h"

#define ENCR_GENERATOR "0xd"
#define ENCR_PRIME "0x7fffffffffffffffffffffffffffffff" /* Mersenne :) */

char text_key[1000];
char *my_public_key_base36;
int key_inited = 0, encryption_keylen;
mpz_t my_private_key, my_public_key, generator, shared_prime;
int my_key_expiry = (time_t)(-1);

static char* mypassphrase;
static int mypassphraselen;

int char_hex_to_bin(int c)
{
  if(isdigit(c))
    return c - '0';
  else
    return tolower(c) - 'a' + 10;
}

int str_hex_to_bin(unsigned char *bin, unsigned char *hex)
{
  int i = 0, j = 0, l = strlen(hex);
cp
  if(l&1)
    {
      i = j = 1;
      bin[0] = char_hex_to_bin(hex[0]);
    }
  for(; i < l; i+=2, j++)
    bin[j] = (char_hex_to_bin(hex[i]) << 4) + char_hex_to_bin(hex[i+1]);
cp
  return j&1?j+1:j;
}

int read_passphrase(char *which, char **out)
{
  FILE *f;
  config_t const *cfg;
  char *filename;
  int size;
  extern char *confbase;
  char *pp;
cp
  if((cfg = get_config_val(passphrasesdir)) == NULL)
    {
      filename = xmalloc(strlen(confbase)+13+strlen(which));
      sprintf(filename, "%spassphrases/%s", confbase, which);
    }
  else
    {
      filename = xmalloc(strlen(cfg->data.ptr)+2+strlen(which));
      sprintf(filename, "%s/%s", (char*)cfg->data.ptr, which);
    }

  if((f = fopen(filename, "rb")) == NULL)
    {
      syslog(LOG_ERR, "Could not open %s: %m", filename);
      return -1;
    }

  fscanf(f, "%d ", &size);
  if(size < 1 || size > (1<<15))
    {
      syslog(LOG_ERR, "Illegal passphrase in %s; size would be %d", filename, size);
      return -1;
    }
  size >>= 2; /* bits->nibbles */
  pp = xmalloc(size+2);
  fgets(pp, size+1, f);
  fclose(f);

  *out = xmalloc(size);
cp
  return str_hex_to_bin(*out, pp);
}

int read_my_passphrase(void)
{
cp
  if((mypassphraselen = read_passphrase("local", &mypassphrase)) < 0)
    return -1;
cp
  return 0;
}

int generate_private_key(void)
{
  FILE *f;
  int i;
  char *s;
  config_t const *cfg;
cp
  if((cfg = get_config_val(keyexpire)) == NULL)
    my_key_expiry = (time_t)(time(NULL) + 3600);
  else
    my_key_expiry = (time_t)(time(NULL) + cfg->data.val);

  syslog(LOG_NOTICE, "Generating %d bits keys.", PRIVATE_KEY_BITS);

  if((f = fopen("/dev/urandom", "r")) == NULL)
    {
      syslog(LOG_ERR, "Opening /dev/urandom failed: %m");
      return -1;
    }

  s = xmalloc((2 * PRIVATE_KEY_LENGTH) + 1);

  for(i = 0; i < PRIVATE_KEY_LENGTH; i++)
    sprintf(&s[i << 1], "%02x", fgetc(f));

  s[2 * PRIVATE_KEY_LENGTH] = '\0';

  mpz_set_str(my_private_key, s, 16);
cp
  return 0;
}

void calculate_public_key(void)
{
cp
  mpz_powm(my_public_key, generator, my_private_key, shared_prime);
  my_public_key_base36 = mpz_get_str(NULL, 36, my_public_key);
cp
}

unsigned char static_key[] = { 0x9c, 0xbf, 0x36, 0xa9, 0xce, 0x20, 0x1b, 0x8b, 0x67, 0x56, 0x21, 0x5d, 0x27, 0x1b, 0xd8, 0x7a };

int security_init(void)
{
cp
  mpz_init(my_private_key);
  mpz_init(my_public_key);
  mpz_init_set_str(shared_prime, ENCR_PRIME, 0);
  mpz_init_set_str(generator, ENCR_GENERATOR, 0);

  if(read_my_passphrase() < 0)
    return -1;
  if(generate_private_key() < 0)
    return -1;

  if(cipher_init(CIPHER_BLOWFISH) < 0)
    return -1;

  calculate_public_key();
cp
  return 0;
}

void set_shared_key(char *almost_key)
{
  char *tmp;
  int len;
  mpz_t ak, our_shared_key;
cp
  mpz_init_set_str(ak, almost_key, 36);
  mpz_init(our_shared_key);
  mpz_powm(our_shared_key, ak, my_private_key, shared_prime);

  tmp = mpz_get_str(NULL, 16, our_shared_key);
  len = str_hex_to_bin(text_key, tmp);

  cipher_set_key(&encryption_key, len, text_key);
  key_inited = 1;
  encryption_keylen = len;

  if(debug_lvl > 2)
    syslog(LOG_INFO, "Encryption key set to %s", tmp);

  free(tmp);
  mpz_clear(ak);
  mpz_clear(our_shared_key);
cp
}


void encrypt_passphrase(passphrase_t *pp)
{
  char key[1000];
  char tmp[1000];
  int len;
  BF_KEY bf_key;
cp  
  mpz_get_str(tmp, 16, my_public_key);
  len = str_hex_to_bin(key, tmp);

  cipher_set_key(&bf_key, len, key);

  low_crypt_key(mypassphrase, pp->phrase, &bf_key, mypassphraselen, BF_ENCRYPT);
  pp->len = ((mypassphraselen - 1) | 7) + 5;

  if(key_inited)
    cipher_set_key(&encryption_key, encryption_keylen, text_key);
cp
}

int verify_passphrase(conn_list_t *cl, unsigned char *his_pubkey)
{
  char key[1000];
  char tmp[1000];
  int len;
  mpz_t pk;
  unsigned char *out;
  BF_KEY bf_key;
  char which[sizeof("123.123.123.123")+1];
  char *meuk;
cp
  mpz_init_set_str(pk, his_pubkey, 36);
  mpz_get_str(tmp, 16, pk);
  len = str_hex_to_bin(key, tmp);
  out = xmalloc(cl->pp->len+3);

  cipher_set_key(&bf_key, len, key);
  low_crypt_key(cl->pp->phrase, out, &bf_key, cl->pp->len, BF_DECRYPT);
  if(key_inited)
    cipher_set_key(&encryption_key, encryption_keylen, text_key);

  sprintf(which, IP_ADDR_S, IP_ADDR_V(cl->vpn_ip));
  if((len = read_passphrase(which, &meuk)) < 0)
    return -1;

  if(memcmp(meuk, out, len))
    return -1;
cp
  return 0;
}

char *make_shared_key(char *pk)
{
  mpz_t tmp, res;
  char *r;
cp
  mpz_init_set_str(tmp, pk, 36);
  mpz_init(res);
  mpz_powm(res, tmp, my_private_key, shared_prime);

  r = mpz_get_str(NULL, 36, res);

  mpz_clear(res);
  mpz_clear(tmp);
cp
  return r;
}

/*
  free a key after overwriting it
*/
void free_key(enc_key_t *k)
{
cp
  if(!k)
    return;
  if(k->key)
    {
      memset(k->key, (char)(-1), k->length);
      free(k->key);
    }
  free(k);
cp
}

void recalculate_encryption_keys(void)
{
  conn_list_t *p;
  char *ek;
cp
  for(p = conn_list; p != NULL; p = p->next)
    {
      if(!p->public_key || !p->public_key->key)
	/* We haven't received a key from this host (yet). */
	continue;
      ek = make_shared_key(p->public_key->key);
      free_key(p->key);
      p->key = xmalloc(sizeof(enc_key_t));
      p->key->length = strlen(ek);
      p->key->expiry = p->public_key->expiry;
      p->key->key = xmalloc(strlen(ek) + 1);
      strcpy(p->key->key, ek);
    }
cp
}

void regenerate_keys(void)
{
cp
  generate_private_key();
  calculate_public_key();
  send_key_changed2();
  recalculate_encryption_keys();
cp
}
