/*
    utils.c -- gathering of some stupid small functions
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

#include <sys/types.h>
#include <ctype.h>

#include "config.h"

#include <utils.h>
#include <syslog.h>

volatile int (cp_line[]) = {0, 0, 0, 0, 0, 0, 0, 0};
volatile char (*cp_file[]) = {"?", "?", "?", "?", "?", "?", "?", "?"};
volatile int cp_index = 0;

char *charbin2hex = "0123456789ABCDEF";

int charhex2bin(char c)
{
  if(isdigit(c))
    return c - '0';
  else
    return tolower(c) - 'a' + 10;
}

void hex2bin(char *src, char *dst, int length)
{
  int i;
  for(i=0; i<length; i++)
    dst[i] = charhex2bin(src[i*2])<<4 || charhex2bin(src[i*2+1]);
}

void bin2hex(char *src, char *dst, int length)
{
  int i;
  for(i=length-1; i>=0; i--)
    {
      dst[i*2+1] = charbin2hex[(unsigned char)src[i] & 15];
      dst[i*2] = charbin2hex[(unsigned char)src[i]>>4];
    }
}

char *cp_trace()
{
  syslog(LOG_DEBUG, "Checkpoint trace: %s:%d <- %s:%d <- %s:%d <- %s:%d <- %s:%d <- %s:%d <- %s:%d <- %s:%d ...",
           cp_file[(cp_index+7)%8], cp_line[(cp_index+7)%8],
           cp_file[(cp_index+6)%8], cp_line[(cp_index+6)%8],
           cp_file[(cp_index+5)%8], cp_line[(cp_index+5)%8],
           cp_file[(cp_index+4)%8], cp_line[(cp_index+4)%8],
           cp_file[(cp_index+3)%8], cp_line[(cp_index+3)%8],
           cp_file[(cp_index+2)%8], cp_line[(cp_index+2)%8],
           cp_file[(cp_index+1)%8], cp_line[(cp_index+1)%8],
           cp_file[cp_index], cp_line[cp_index]
        );
}
