#ifndef TINC_SCRIPT_H
#define TINC_SCRIPT_H

/*
    script.h -- header file for script.c
    Copyright (C) 1999-2005 Ivo Timmermans,
                  2000-2017 Guus Sliepen <guus@tinc-vpn.org>

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

typedef struct environment {
	int n;
	int size;
	char **entries;
} environment_t;

extern int environment_add(environment_t *env, const char *format, ...);
extern int environment_placeholder(environment_t *env);
extern void environment_update(environment_t *env, int pos, const char *format, ...);
extern void environment_init(environment_t *env);
extern void environment_exit(environment_t *env);

extern bool execute_script(const char *name, environment_t *env);

#endif
