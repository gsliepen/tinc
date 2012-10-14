/*
    control_protocol.h -- control socket protocol.
    Copyright (C) 2007      Scott Lamb <slamb@slamb.org>
                  2009-2012 Guus Sliepen <guus@tinc-vpn.org>

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

#ifndef __TINC_CONTROL_PROTOCOL_H__
#define __TINC_CONTROL_PROTOCOL_H__

#include "protocol.h"

enum request_type {
	REQ_INVALID = -1,
	REQ_STOP = 0,
	REQ_RELOAD,
	REQ_RESTART,
	REQ_DUMP_NODES,
	REQ_DUMP_EDGES,
	REQ_DUMP_SUBNETS,
	REQ_DUMP_CONNECTIONS,
	REQ_DUMP_GRAPH,
	REQ_PURGE,
	REQ_SET_DEBUG,
	REQ_RETRY,
	REQ_CONNECT,
	REQ_DISCONNECT,
	REQ_DUMP_TRAFFIC,
	REQ_PCAP,
	REQ_LOG,
};

#define TINC_CTL_VERSION_CURRENT 0

#endif
