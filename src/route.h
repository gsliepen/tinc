/*
    route.h -- header file for route.c
    Copyright (C) 2000-2002 Ivo Timmermans <zarq@iname.com>
                  2000-2002 Guus Sliepen <guus@sliepen.warande.net>         

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

    $Id: route.h,v 1.1.2.7 2002/03/01 14:09:31 guus Exp $
*/

#ifndef __TINC_ROUTE_H__
#define __TINC_ROUTE_H__

enum
{
  RMODE_HUB = 0,
  RMODE_SWITCH,
  RMODE_ROUTER,
};

extern int routing_mode;
extern int priorityinheritance;
extern int macexpire;

extern void age_mac(void);
extern void route_incoming(node_t *, vpn_packet_t *);
extern void route_outgoing(vpn_packet_t *);

#endif /* __TINC_ROUTE_H__ */
