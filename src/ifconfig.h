#ifndef TINC_IFCONFIG_H
#define TINC_IFCONFIG_H

/*
    ifconfig.h -- header for ifconfig.c.
    Copyright (C) 2016 Guus Sliepen <guus@tinc-vpn.org>

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

extern void ifconfig_dhcp(FILE *out);
extern void ifconfig_dhcp6(FILE *out);
extern void ifconfig_slaac(FILE *out);
extern void ifconfig_address(FILE *out, const char *value);
extern void ifconfig_route(FILE *out, const char *value);
extern void ifconfig_header(FILE *out);
extern bool ifconfig_footer(FILE *out);

#endif
