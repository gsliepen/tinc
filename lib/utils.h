/*
    utils.h -- header file for utils.c
    Copyright (C) 1999-2001 Ivo Timmermans <zarq@iname.com>
                  2000,2001 Guus Sliepen <guus@sliepen.warande.net>

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
  DEBUG_NOTHING = 0,		/* Quiet mode, only show starting/stopping of the daemon */
  DEBUG_CONNECTIONS = 1,	/* Show (dis)connects of other tinc daemons via TCP */
  DEBUG_ERROR = 2,		/* Show error messages received from other hosts */
  DEBUG_STATUS = 2,		/* Show status messages received from other hosts */
  DEBUG_PROTOCOL = 3,		/* Show the requests that are sent/received */
  DEBUG_META = 4,		/* Show contents of every request that is sent/received */
  DEBUG_TRAFFIC = 5,		/* Show network traffic information */
  DEBUG_PACKET = 6,		/* Show contents of each packet that is being sent/received */
  DEBUG_SCARY_THINGS = 10	/* You have been warned */
};

#define min(a,b) (((a)<(b))?(a):(b))

#ifdef ENABLE_TRACING
extern volatile int cp_line[];
extern volatile char *cp_file[];
extern volatile int cp_index;
extern void cp_trace(void);

  #define cp { cp_line[cp_index] = __LINE__; cp_file[cp_index] = __FILE__; cp_index++; cp_index %= 16; }
  #define ecp { fprintf(stderr, "Explicit checkpoint in %s line %d\n", __FILE__, __LINE__); }
#else
  #define cp
  #define ecp
  #define cp_trace()
#endif

extern void hex2bin(char *src, char *dst, int length);
extern void bin2hex(char *src, char *dst, int length);

#endif /* __TINC_UTILS_H__ */
