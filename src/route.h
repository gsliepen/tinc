/*
    route.h -- header file for route.c
    Copyright (C) 2000 Ivo Timmermans <zarq@iname.com>
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

    $Id: route.h,v 1.1.2.1 2001/01/07 15:27:30 guus Exp $
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

extern connection_t *route_incoming(connection_t *, vpn_packet_t *);
extern connection_t *route_outgoing(connection_t *, vpn_packet_t *);

#endif /* __TINC_ROUTE_H__ */
