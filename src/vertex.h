/*
    vertex.h -- header for vertex.c
    Copyright (C) 2001 Guus Sliepen <guus@sliepen.warande.net>,
                  2001 Ivo Timmermans <itimmermans@bigfoot.com>

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

    $Id: vertex.h,v 1.1.2.2 2001/10/09 19:37:10 guus Exp $
*/

typedef struct vertex_t {
  struct halfconnection_t *from;
  struct halfconnection_t *to;
  long int options;                /* options turned on for this connection */
} vertex_t;

typedef struct halfconnection_t {
  struct node_t *node;

  ipv4_t address;                  /* real (internet) ip on this end of the meta connection */
  short unsigned int port;         /* port number of this end of the meta connection */
  char *hostname;                  /* the hostname of real ip */
  
  /* Following bits only used when this is a connection with ourself. */
  
  RSA *rsa_key;                    /* RSA key used for authentication */
  EVP_CIPHER *cipher;              /* Cipher type for meta protocol */ 
  EVP_CIPHER_CTX *ctx;             /* Cipher state for meta protocol */
  char *key;                       /* Cipher key + iv */
  int keylength;                   /* Cipher keylength */
  char *challenge;                 /* Challenge sent to this end */
} halfconnection_t;
