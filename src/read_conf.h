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

    $Id: read_conf.h,v 1.2 2002/05/02 11:50:07 zarq Exp $
*/

#ifndef __TINC_READ_CONF_H__
#define __TINC_READ_CONF_H__

#include <avl_tree.h>

extern int read_config_file(avl_tree_t *, const char *);
extern int read_server_config(void);
extern FILE *ask_and_safe_open(const char*, const char*, const char *);
extern int is_safe_path(const char *);

#endif /* __TINC_READ_CONF_H__ */
