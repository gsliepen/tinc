/*
    interface.h -- header for interface.c
    Copyright (C) 2002 Guus Sliepen <guus@sliepen.warande.net>,
                  2002 Ivo Timmermans <itimmermans@bigfoot.com>

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

    $Id: interface.h,v 1.1 2002/04/11 14:23:56 zarq Exp $
*/

#ifndef __TINC_INTERFACE_H__
#define __TINC_INTERFACE_H__

#include <gtk/gtk.h>

#include "node.h"
#include "edge.h"

typedef struct graph_t {
  struct graph_t *attractors[20];
  struct graph_t *repellors[20];
  int nat;
  int nrp;
  node_t *node;
} graph_t;

extern int build_graph;

void log_message(int, const char *, ...);
GtkCTreeNode *if_node_add(node_t *);
void if_node_del(node_t *);
void if_subnet_add(subnet_t *);
void if_subnet_del(subnet_t *);
void if_edge_add(edge_t *);
void if_edge_del(edge_t *);

void if_build_graph(void);
void if_graph_add_node(node_t *);
void if_graph_add_edge(edge_t *);

int init_interface(void);

#endif /* __TINC_INTERFACE_H__ */
