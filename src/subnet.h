/*
    subnet.h -- header for subnet.c
    Copyright (C) 2000 Guus Sliepen <guus@sliepen.warande.net>,
                  2000 Ivo Timmermans <itimmermans@bigfoot.com>

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

    $Id: subnet.h,v 1.1.2.1 2000/10/01 03:21:49 guus Exp $
*/

#ifndef __TINC_SUBNET_H__
#define __TINC_SUBNET_H__

enum{
  SUBNET_MAC = 0,
  SUBNET_IPv4,
  SUBNET_IPv6,
};

typedef struct subnet_t {
  struct conn_list_t *owner;		/* the owner of this subnet */
  struct conn_list_t *uplink;		/* the uplink which we should send packets to for this subnet */

  struct subnet_t *prev;		/* previous subnet_t for this owner */
  struct subnet_t *next;		/* next subnet_t for this owner */

  int type;				/* subnet type (IPv4? IPv6? MAC? something even weirder?) */

  /* Okay this is IPv4 specific because we are lazy and don't want to implement
     other types just now. Type should always be SUBNET_IPv4 for now. */

  ip_t netaddr;
  ip_t netmask;
} subnet_t;  

#endif /* __TINC_SUBNET_H__ */
