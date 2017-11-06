#ifndef TINC_CONF_H
#define TINC_CONF_H

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

#include "list.h"
#include "splay_tree.h"
#include "subnet.h"

typedef struct config_t {
	char *variable;
	char *value;
	char *file;
	int line;
} config_t;


extern splay_tree_t *config_tree;

extern int pinginterval;
extern int pingtimeout;
extern int maxtimeout;
extern bool bypass_security;
extern list_t *cmdline_conf;

extern void init_configuration(splay_tree_t **config_tree);
extern void exit_configuration(splay_tree_t **config_tree);
extern config_t *new_config(void) __attribute__((__malloc__));
extern void free_config(config_t *config);
extern void config_add(splay_tree_t *config_tree, config_t *config);
extern config_t *lookup_config(splay_tree_t *config_tree, char *variable);
extern config_t *lookup_config_next(splay_tree_t *config_tree, const config_t *config);
extern bool get_config_bool(const config_t *config, bool *result);
extern bool get_config_int(const config_t *config, int *result);
extern bool get_config_string(const config_t *config, char **result);
extern bool get_config_address(const config_t *config, struct addrinfo **result);
extern bool get_config_subnet(const config_t *config, struct subnet_t **result);

extern config_t *parse_config_line(char *line, const char *fname, int lineno);
extern bool read_config_file(splay_tree_t *config_tree, const char *filename, bool verbose);
extern void read_config_options(splay_tree_t *config_tree, const char *prefix);
extern bool read_server_config(void);
extern bool read_host_config(splay_tree_t *config_tree, const char *name, bool verbose);
extern bool append_config_file(const char *name, const char *key, const char *value);

#endif
