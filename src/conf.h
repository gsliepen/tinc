/*
    conf.h -- header for conf.c
    Copyright (C) 1998-2002 Ivo Timmermans <itimmermans@bigfoot.com>
                  2000-2002 Guus Sliepen <guus@sliepen.warande.net>

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

    $Id: conf.h,v 1.6.4.32 2002/02/18 16:25:16 guus Exp $
*/

#ifndef __TINC_CONF_H__
#define __TINC_CONF_H__

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include <avl_tree.h>
#include "net.h"
#include "subnet.h"

typedef struct config_t {
  char *variable;
  char *value;
  char *file;
  int line;
} config_t;

extern avl_tree_t *config_tree;

extern int debug_lvl;
extern int pingtimeout;
extern int maxtimeout;
extern int bypass_security;
extern char *confbase;
extern char *netname;

extern void init_configuration(avl_tree_t **);
extern void exit_configuration(avl_tree_t **);
extern config_t *new_config(void);
extern void free_config(config_t *);
extern void config_add(avl_tree_t *, config_t *);
extern config_t *lookup_config(avl_tree_t *, char *);
extern config_t *lookup_config_next(avl_tree_t *, config_t *);
extern int get_config_bool(config_t *, int *);
extern int get_config_int(config_t *, int *);
extern int get_config_port(config_t *, port_t *);
extern int get_config_string(config_t *, char **);
extern int get_config_address(config_t *, struct addrinfo **);
struct subnet_t; /* Needed for next line. */
extern int get_config_subnet(config_t *, struct subnet_t **);

extern int read_config_file(avl_tree_t *, const char *);
extern int read_server_config(void);
extern FILE *ask_and_safe_open(const char*, const char*, const char *);
extern int is_safe_path(const char *);

#endif /* __TINC_CONF_H__ */
