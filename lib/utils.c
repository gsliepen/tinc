/*
    utils.c -- gathering of some stupid small functions
    Copyright (C) 1999 Ivo Timmermans <zarq@iname.com>

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

volatile int cp_line;
volatile char *cp_file;

char *charbin2hex = "0123456789ABCDEF";

int charhex2bin(char c)
{
  if(isdigit(c))
    return c - '0';
  else
    return tolower(c) - 'a' + 10;
}

void hex2bin(char *src, char *dst, size_t length)
{
  size_t i;
  for(i=0; i<length; i++)
    dst[i] = charhex2bin(src[i*2])<<4 || charhex2bin(src[i*2+1]);
}

void bin2hex(char *src, char *dst, size_t length)
{
  size_t i;
  for(i=length-1; i>=0; i--)
    {
      dst[i*2+1] = charbin2hex[src[i] & 15];
      dst[i*2] = charbin2hex[src[i]>>4];
    }
}
