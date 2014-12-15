/*
    conf.h -- header for conf.c
    Copyright (C) 1998-2005 Ivo Timmermans
                  2000-2013 Guus Sliepen <guus@tinc-vpn.org>

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

#ifndef __TINC_CONF_H__
#define __TINC_CONF_H__

#include "splay_tree.h"
#include "list.h"

typedef struct config_t {
	char *variable;
	char *value;
	char *file;
	int line;
} config_t;

#include "subnet.h"

extern splay_tree_t *config_tree;

extern int pinginterval;
extern int pingtimeout;
extern int keepaliveinterval;
extern int maxtimeout;
extern bool bypass_security;
extern list_t *cmdline_conf;

extern void init_configuration(splay_tree_t **);
extern void exit_configuration(splay_tree_t **);
extern config_t *new_config(void) __attribute__ ((__malloc__));
extern void free_config(config_t *);
extern void config_add(splay_tree_t *, config_t *);
extern config_t *lookup_config(splay_tree_t *, char *);
extern config_t *lookup_config_next(splay_tree_t *, const config_t *);
extern bool get_config_bool(const config_t *, bool *);
extern bool get_config_int(const config_t *, int *);
extern bool get_config_string(const config_t *, char **);
extern bool get_config_address(const config_t *, struct addrinfo **);
extern bool get_config_subnet(const config_t *, struct subnet_t **);

extern config_t *parse_config_line(char *, const char *, int);
extern bool read_config_file(splay_tree_t *, const char *);
extern void read_config_options(splay_tree_t *, const char *);
extern bool read_server_config(void);
extern bool read_host_config(splay_tree_t *, const char *);
extern bool append_config_file(const char *, const char *, const char *);

#endif /* __TINC_CONF_H__ */
