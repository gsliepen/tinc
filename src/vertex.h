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

    $Id: vertex.h,v 1.1.2.4 2001/10/10 20:35:10 guus Exp $
*/

#ifndef __TINC_VERTEX_H__
#define __TINC_VERTEX_H__

#include <avl_tree.h>

#include "node.h"
#include "connection.h"

typedef struct halfconnection_t {
  struct node_t *node;             /* node associated with this end of the connection */

  ipv4_t address;                  /* real (internet) ip on this end of the meta connection */
  short unsigned int port;         /* port number of this end of the meta connection */
  char *hostname;                  /* the hostname of real ip */
} halfconnection_t;

typedef struct vertex_t {
  struct halfconnection_t from;
  struct halfconnection_t to;

  long int options;                /* options turned on for this connection */
  int metric;                      /* weight of this vertex */
  
  struct connection_t *connection; /* connection associated with this vertex, if available */
} vertex_t;

extern avl_tree_t *vertex_tree;    /* Tree with all known vertices (replaces active_tree) */

#endif /* __TINC_VERTEX_H__ */
