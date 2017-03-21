/*
    names.h -- header for names.c
    Copyright (C) 1998-2005 Ivo Timmermans
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

#ifndef __TINC_NAMES_H__
#define __TINC_NAMES_H__

extern char *confdir;
extern char *confbase;
extern bool confbase_given;
extern char *netname;
extern char *myname;
extern char *identname;
extern char *unixsocketname;
extern char *logfilename;
extern char *pidfilename;
extern char *program_name;

extern void make_names(bool daemon);
extern void free_names(void);

#endif /* __TINC_NAMES_H__ */
