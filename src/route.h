#ifndef TINC_ROUTE_H
#define TINC_ROUTE_H

/*
    route.h -- header file for route.c
    Copyright (C) 2000-2005 Ivo Timmermans
                  2000-2012 Guus Sliepen <guus@tinc-vpn.org>

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

#include "net.h"
#include "node.h"

typedef enum rmode_t {
	RMODE_HUB = 0,
	RMODE_SWITCH,
	RMODE_ROUTER,
} rmode_t;

typedef enum fmode_t {
	FMODE_OFF = 0,
	FMODE_INTERNAL,
	FMODE_KERNEL,
} fmode_t;

typedef enum bmode_t {
	BMODE_NONE = 0,
	BMODE_MST,
	BMODE_DIRECT,
} bmode_t;

extern rmode_t routing_mode;
extern fmode_t forwarding_mode;
extern bmode_t broadcast_mode;
extern bool decrement_ttl;
extern bool directonly;
extern bool overwrite_mac;
extern bool priorityinheritance;
extern int macexpire;

extern mac_t mymac;

extern void age_subnets(void);
extern void route(struct node_t *source, struct vpn_packet_t *packet);

#endif
