/*
    utils.c -- gathering of some stupid small functions
    Copyright (C) 1999-2005 Ivo Timmermans <zarq@iname.com>
                  2000-2006 Guus Sliepen <guus@tinc-vpn.org>

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

#include "system.h"

#include "../src/logger.h"
#include "utils.h"

#ifdef ENABLE_TRACING
volatile int (cp_line[]) = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
volatile char (*cp_file[]) = {"?", "?", "?", "?", "?", "?", "?", "?", "?", "?", "?", "?", "?", "?", "?", "?"};
volatile int cp_index = 0;
#endif

char *hexadecimals = "0123456789ABCDEF";

int charhex2bin(char c)
{
	if(isdigit(c))
		return c - '0';
	else
		return toupper(c) - 'A' + 10;
}


void hex2bin(char *src, char *dst, int length)
{
	int i;
	for(i = 0; i < length; i++)
		dst[i] = charhex2bin(src[i * 2]) * 16 + charhex2bin(src[i * 2 + 1]);
}

void bin2hex(char *src, char *dst, int length)
{
	int i;
	for(i = length - 1; i >= 0; i--) {
		dst[i * 2 + 1] = hexadecimals[(unsigned char) src[i] & 15];
		dst[i * 2] = hexadecimals[(unsigned char) src[i] >> 4];
	}
}

#ifdef ENABLE_TRACING
void cp_trace()
{
	logger(LOG_DEBUG, "Checkpoint trace: %s:%d <- %s:%d <- %s:%d <- %s:%d <- %s:%d <- %s:%d <- %s:%d <- %s:%d <- %s:%d <- %s:%d <- %s:%d <- %s:%d <- %s:%d <- %s:%d <- %s:%d <- %s:%d...",
		   cp_file[(cp_index + 15) % 16], cp_line[(cp_index + 15) % 16],
		   cp_file[(cp_index + 14) % 16], cp_line[(cp_index + 14) % 16],
		   cp_file[(cp_index + 13) % 16], cp_line[(cp_index + 13) % 16],
		   cp_file[(cp_index + 12) % 16], cp_line[(cp_index + 12) % 16],
		   cp_file[(cp_index + 11) % 16], cp_line[(cp_index + 11) % 16],
		   cp_file[(cp_index + 10) % 16], cp_line[(cp_index + 10) % 16],
		   cp_file[(cp_index + 9) % 16], cp_line[(cp_index + 9) % 16],
		   cp_file[(cp_index + 8) % 16], cp_line[(cp_index + 8) % 16],
		   cp_file[(cp_index + 7) % 16], cp_line[(cp_index + 7) % 16],
		   cp_file[(cp_index + 6) % 16], cp_line[(cp_index + 6) % 16],
		   cp_file[(cp_index + 5) % 16], cp_line[(cp_index + 5) % 16],
		   cp_file[(cp_index + 4) % 16], cp_line[(cp_index + 4) % 16],
		   cp_file[(cp_index + 3) % 16], cp_line[(cp_index + 3) % 16],
		   cp_file[(cp_index + 2) % 16], cp_line[(cp_index + 2) % 16],
		   cp_file[(cp_index + 1) % 16], cp_line[(cp_index + 1) % 16],
		   cp_file[cp_index], cp_line[cp_index]
		);
}
#endif

#if defined(HAVE_MINGW) || defined(HAVE_CYGWIN)
#ifdef HAVE_CYGWIN
#include <w32api/windows.h>
#endif

char *winerror(int err) {
	static char buf[1024], *newline;

	if (!FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
	        NULL, err, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), buf, sizeof(buf), NULL)) {
		strncpy(buf, _("(unable to format errormessage)"), sizeof(buf));
	};

	if((newline = strchr(buf, '\r')))
		*newline = '\0';

	return buf;
}
#endif

