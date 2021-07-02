/*
    hash.c -- hash table management
    Copyright (C) 2012-2013 Guus Sliepen <guus@tinc-vpn.org>

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

#include "system.h"

#include "hash.h"
#include "xalloc.h"

uint32_t modulo(uint32_t hash, size_t n) {
	if(n == 0x100) {
		return (hash >> 24) ^ ((hash >> 16) & 0xff) ^ ((hash >> 8) & 0xff) ^ (hash & 0xff);
	} else if(n == 0x10000) {
		return (hash >> 16) ^ (hash & 0xffff);
	} else {
		return hash % n;
	}
}
