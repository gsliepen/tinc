#ifndef TINC_CONF_H
#define TINC_CONF_H

/*
    conf.h -- header for conf.c
    Copyright (C) 1998-2005 Ivo Timmermans
                  2000-2012 Guus Sliepen <guus@tinc-vpn.org>

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

#include "avl_tree.h"
#include "list.h"

typedef struct config_t {
	char *variable;
	char *value;
	char *file;
	int line;
} config_t;

#include "subnet.h"

extern avl_tree_t *config_tree;

extern int pinginterval;
extern int pingtimeout;
extern int maxtimeout;
extern int mintimeout;
extern bool bypass_security;
extern char *confbase;
extern char *netname;
extern list_t *cmdline_conf;

extern void init_configuration(avl_tree_t **config_tree);
extern void exit_configuration(avl_tree_t **config_tree);
extern config_t *new_config(void) __attribute__((__malloc__));
extern void free_config(config_t *cfg);
extern void config_add(avl_tree_t *config_tree, config_t *cfg);
extern config_t *lookup_config(const avl_tree_t *config_tree, char *variable);
extern config_t *lookup_config_next(const avl_tree_t *config_tree, const config_t *cfg);
extern bool get_config_bool(const config_t *cfg, bool *result);
extern bool get_config_int(const config_t *cfg, int *result);
extern bool get_config_string(const config_t *cfg, char **result);
extern bool get_config_address(const config_t *cfg, struct addrinfo **result);
extern bool get_config_subnet(const config_t *cfg, struct subnet_t **result);

extern config_t *parse_config_line(char *line, const char *fname, int lineno);
extern bool read_config_file(avl_tree_t *config_tree, const char *fname);
extern void read_config_options(avl_tree_t *config_tree, const char *prefix);
extern bool read_server_config(void);
extern bool read_connection_config(struct connection_t *c);
extern FILE *ask_and_open(const char *fname, const char *what);

#endif
