/*
    conf.h -- header for conf.c
    Copyright (C) 1998-2003 Ivo Timmermans <ivo@o2w.nl>
                  2000-2003 Guus Sliepen <guus@sliepen.eu.org>

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

    $Id: conf.h,v 1.6.4.42 2003/07/30 21:52:41 guus Exp $
*/

#ifndef __TINC_CONF_H__
#define __TINC_CONF_H__

#include "avl_tree.h"

typedef struct config_t {
	char *variable;
	char *value;
	char *file;
	int line;
} config_t;

#include "subnet.h"

extern avl_tree_t *config_tree;

extern int pingtimeout;
extern int maxtimeout;
extern bool bypass_security;
extern char *confbase;
extern char *netname;

extern void init_configuration(avl_tree_t **);
extern void exit_configuration(avl_tree_t **);
extern config_t *new_config(void) __attribute__ ((__malloc__));
extern void free_config(config_t *);
extern void config_add(avl_tree_t *, config_t *);
extern config_t *lookup_config(const avl_tree_t *, char *);
extern config_t *lookup_config_next(const avl_tree_t *, const config_t *);
extern bool get_config_bool(const config_t *, bool *);
extern bool get_config_int(const config_t *, int *);
extern bool get_config_string(const config_t *, char **);
extern bool get_config_address(const config_t *, struct addrinfo **);
extern bool get_config_subnet(const config_t *, struct subnet_t **);

extern int read_config_file(avl_tree_t *, const char *);
extern bool read_server_config(void);
extern FILE *ask_and_safe_open(const char *, const char *, bool, const char *);
extern bool is_safe_path(const char *);

#endif							/* __TINC_CONF_H__ */
