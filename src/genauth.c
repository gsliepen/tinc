/*
    genauth.c -- generate public/private keypairs
    Copyright (C) 1998,1999,2000 Ivo Timmermans <zarq@iname.com>
                            2000 Guus Sliepen <guus@sliepen.warande.net>

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

    $Id: genauth.c,v 1.7.4.4 2000/10/20 15:34:35 guus Exp $
*/

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <openssl/rsa.h>
#include <openssl/rand.h>

#include <xalloc.h>

#include "system.h"

#define RSA_PUBLIC_EXPONENT 65535

void indicator(int a, int b, void *p)
{
  switch(a)
  {
    case 0:
      fprintf(stderr, ".");
      break;
    case 1:
      fprintf(stderr, "+");
      break;
    case 2:
      fprintf(stderr, "-");
      break;
    case 3:
      switch(b)
        {
          case 0:
            fprintf(stderr, " p\n");      
            break;
          case 1:
            fprintf(stderr, " q\n");
            break;
          default:
            fprintf(stderr, "?");
         }
       break;
    default:
      fprintf(stderr, "?");
  }
}

int main(int argc, char **argv)
{
  int bits;
  RSA *key;

  setlocale (LC_ALL, "");
  bindtextdomain (PACKAGE, LOCALEDIR);
  textdomain (PACKAGE);

  if(argc > 2 || (argc == 2 && (!strcmp(argv[1], "-h") || !strcmp(argv[1], "--help"))))
    {
      fprintf(stderr, _("Usage: %s bits\n"), argv[0]);
      return 1;
    }

  if(!argv[1])
    argv[1] = "1024";
    
  bits = atol(argv[1]);

  if(bits<32)
    {
      fprintf(stderr, _("Illegal number: %s\n"), argv[1]);
      return 1;
    }
    
  bits = ((bits - 1) | 7) + 1;		/* Align to bytes for easy mallocing and reading */

  fprintf(stderr, _("Seeding the PRNG: please press some keys or move\nthe mouse if this program seems to have halted...\n"));

  RAND_load_file("/dev/random", 1024);	/* OpenSSL PRNG state apparently uses 1024 bytes */

  fprintf(stderr, _("Generating %d bits keys:\n"), bits);

  key = RSA_generate_key(bits, RSA_PUBLIC_EXPONENT, indicator, NULL);

  fprintf(stderr, _("Done.\n"));

  printf(_("Public key:  %s\n"), BN_bn2hex(key->n));
  printf(_("Private key: %s\n"), BN_bn2hex(key->d));
  printf(_("Public exp:  %s\n"), BN_bn2hex(key->e));

  fflush(stdin);	/* Flush any input caused by random keypresses */

  return 0;
}
