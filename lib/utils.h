/*
    utils.h -- header file for utils.c
    Copyright (C) 1999,2000 Ivo Timmermans <zarq@iname.com>
                       2000 Guus Sliepen <guus@sliepen.warande.net>

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
*/

#ifndef __TINC_UTILS_H__
#define __TINC_UTILS_H__

#include <ctype.h>

enum {
  DEBUG_CONNECTIONS = 0,
  DEBUG_PROTOCOL,
  DEBUG_STATUS,
  DEBUG_ERROR,
  DEBUG_META
};

#define min(a,b) (((a)<(b))?(a):(b))

extern volatile int cp_line[];
extern volatile char *cp_file[];
extern volatile int cp_index;

#define cp { cp_line[cp_index] = __LINE__; cp_file[cp_index] = __FILE__; cp_index++; cp_index %= 8; }
#define ecp { fprintf(stderr, "Explicit checkpoint in %s line %d\n", __FILE__, __LINE__); }

extern void hex2bin(char *src, char *dst, int length);
extern void bin2hex(char *src, char *dst, int length);
extern char *cp_trace(void);

#endif /* __TINC_UTILS_H__ */
