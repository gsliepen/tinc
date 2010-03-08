/*
    protocol_subnet.c -- handle the meta-protocol, subnets
    Copyright (C) 1999-2005 Ivo Timmermans,
                  2000-2009 Guus Sliepen <guus@tinc-vpn.org>
                  2009      Michael Tokarev <mjt@tls.msk.ru>

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

#include "conf.h"
#include "connection.h"
#include "logger.h"
#include "net.h"
#include "netutl.h"
#include "node.h"
#include "protocol.h"
#include "subnet.h"
#include "utils.h"
#include "xalloc.h"

bool send_add_subnet(connection_t *c, const subnet_t *subnet) {
	char netstr[MAXNETSTR];

	if(!net2str(netstr, sizeof netstr, subnet))
		return false;

	return send_request(c, "%d %x %s %s", ADD_SUBNET, rand(), subnet->owner->name, netstr);
}

bool add_subnet_h(connection_t *c) {
	char subnetstr[MAX_STRING_SIZE];
	char name[MAX_STRING_SIZE];
	node_t *owner;
	subnet_t s = {0}, *new, *old;

	if(sscanf(c->buffer, "%*d %*x " MAX_STRING " " MAX_STRING, name, subnetstr) != 2) {
		logger(LOG_ERR, "Got bad %s from %s (%s)", "ADD_SUBNET", c->name,
			   c->hostname);
		return false;
	}

	/* Check if owner name is valid */

	if(!check_id(name)) {
		logger(LOG_ERR, "Got bad %s from %s (%s): %s", "ADD_SUBNET", c->name,
			   c->hostname, "invalid name");
		return false;
	}

	/* Check if subnet string is valid */

	if(!str2net(&s, subnetstr)) {
		logger(LOG_ERR, "Got bad %s from %s (%s): %s", "ADD_SUBNET", c->name,
			   c->hostname, "invalid subnet string");
		return false;
	}

	if(seen_request(c->buffer))
		return true;

	/* Check if the owner of the new subnet is in the connection list */

	owner = lookup_node(name);

	if(tunnelserver && owner != myself && owner != c->node) {
		/* in case of tunnelserver, ignore indirect subnet registrations */
		ifdebug(PROTOCOL) logger(LOG_WARNING, "Ignoring indirect %s from %s (%s) for %s",
				   "ADD_SUBNET", c->name, c->hostname, subnetstr);
		return true;
	}

	if(!owner) {
		owner = new_node();
		owner->name = xstrdup(name);
		node_add(owner);
	}

	/* Check if we already know this subnet */

	if(lookup_subnet(owner, &s))
		return true;

	/* If we don't know this subnet, but we are the owner, retaliate with a DEL_SUBNET */

	if(owner == myself) {
		ifdebug(PROTOCOL) logger(LOG_WARNING, "Got %s from %s (%s) for ourself",
				   "ADD_SUBNET", c->name, c->hostname);
		s.owner = myself;
		send_del_subnet(c, &s);
		return true;
	}

	/* In tunnel server mode, we should already know all allowed subnets */

	if(tunnelserver) {
		logger(LOG_WARNING, "Ignoring unauthorized %s from %s (%s): %s",
				"ADD_SUBNET", c->name, c->hostname, subnetstr);
		return true;
	}

	/* Ignore if strictsubnets is true, but forward it to others */

	if(strictsubnets) {
		logger(LOG_WARNING, "Ignoring unauthorized %s from %s (%s): %s",
				"ADD_SUBNET", c->name, c->hostname, subnetstr);
		forward_request(c);
		return true;
	}

	/* If everything is correct, add the subnet to the list of the owner */

	*(new = new_subnet()) = s;
	subnet_add(owner, new);

	if(owner->status.reachable)
		subnet_update(owner, new, true);

	/* Tell the rest */

	forward_request(c);

	/* Fast handoff of roaming MAC addresses */

	if(s.type == SUBNET_MAC && owner != myself && (old = lookup_subnet(myself, &s)) && old->expires)
		old->expires = now;

	return true;
}

bool send_del_subnet(connection_t *c, const subnet_t *s) {
	char netstr[MAXNETSTR];

	if(!net2str(netstr, sizeof netstr, s))
		return false;

	return send_request(c, "%d %x %s %s", DEL_SUBNET, rand(), s->owner->name, netstr);
}

bool del_subnet_h(connection_t *c) {
	char subnetstr[MAX_STRING_SIZE];
	char name[MAX_STRING_SIZE];
	node_t *owner;
	subnet_t s = {0}, *find;

	if(sscanf(c->buffer, "%*d %*x " MAX_STRING " " MAX_STRING, name, subnetstr) != 2) {
		logger(LOG_ERR, "Got bad %s from %s (%s)", "DEL_SUBNET", c->name,
			   c->hostname);
		return false;
	}

	/* Check if owner name is valid */

	if(!check_id(name)) {
		logger(LOG_ERR, "Got bad %s from %s (%s): %s", "DEL_SUBNET", c->name,
			   c->hostname, "invalid name");
		return false;
	}

	/* Check if subnet string is valid */

	if(!str2net(&s, subnetstr)) {
		logger(LOG_ERR, "Got bad %s from %s (%s): %s", "DEL_SUBNET", c->name,
			   c->hostname, "invalid subnet string");
		return false;
	}

	if(seen_request(c->buffer))
		return true;

	/* Check if the owner of the subnet being deleted is in the connection list */

	owner = lookup_node(name);

	if(tunnelserver && owner != myself && owner != c->node) {
		/* in case of tunnelserver, ignore indirect subnet deletion */
		ifdebug(PROTOCOL) logger(LOG_WARNING, "Ignoring indirect %s from %s (%s) for %s",
                                  "DEL_SUBNET", c->name, c->hostname, subnetstr);
		return true;
	}

	if(!owner) {
		ifdebug(PROTOCOL) logger(LOG_WARNING, "Got %s from %s (%s) for %s which is not in our node tree",
				   "DEL_SUBNET", c->name, c->hostname, name);
		return true;
	}

	/* If everything is correct, delete the subnet from the list of the owner */

	s.owner = owner;

	find = lookup_subnet(owner, &s);

	if(!find) {
		ifdebug(PROTOCOL) logger(LOG_WARNING, "Got %s from %s (%s) for %s which does not appear in his subnet tree",
				   "DEL_SUBNET", c->name, c->hostname, name);
		if(strictsubnets)
			forward_request(c);
		return true;
	}

	/* If we are the owner of this subnet, retaliate with an ADD_SUBNET */

	if(owner == myself) {
		ifdebug(PROTOCOL) logger(LOG_WARNING, "Got %s from %s (%s) for ourself",
				   "DEL_SUBNET", c->name, c->hostname);
		send_add_subnet(c, find);
		return true;
	}

	if(tunnelserver)
		return true;

	/* Tell the rest */

	forward_request(c);
	if(strictsubnets)
		return true;

	/* Finally, delete it. */

	if(owner->status.reachable)
		subnet_update(owner, find, false);

	subnet_del(owner, find);

	return true;
}
