/*
    protocol_edge.c -- handle the meta-protocol, edges
    Copyright (C) 1999-2003 Ivo Timmermans <ivo@o2w.nl>,
                  2000-2003 Guus Sliepen <guus@sliepen.eu.org>

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

    $Id: protocol_edge.c,v 1.1.4.22 2003/11/10 22:31:53 guus Exp $
*/

#include "system.h"

#include "avl_tree.h"
#include "conf.h"
#include "connection.h"
#include "edge.h"
#include "graph.h"
#include "logger.h"
#include "meta.h"
#include "net.h"
#include "netutl.h"
#include "node.h"
#include "protocol.h"
#include "utils.h"
#include "xalloc.h"

bool send_add_edge(connection_t *c, const edge_t *e)
{
	bool x;
	char *address, *port;

	cp();

	sockaddr2str(&e->address, &address, &port);

	x = send_request(c, "%d %lx %s %s %s %s %lx %d", ADD_EDGE, random(),
					 e->from->name, e->to->name, address, port,
					 e->options, e->weight);
	free(address);
	free(port);

	return x;
}

bool add_edge_h(connection_t *c)
{
	edge_t *e;
	node_t *from, *to;
	char from_name[MAX_STRING_SIZE];
	char to_name[MAX_STRING_SIZE];
	char to_address[MAX_STRING_SIZE];
	char to_port[MAX_STRING_SIZE];
	sockaddr_t address;
	long int options;
	int weight;

	cp();

	if(sscanf(c->buffer, "%*d %*x "MAX_STRING" "MAX_STRING" "MAX_STRING" "MAX_STRING" %lx %d",
			  from_name, to_name, to_address, to_port, &options, &weight) != 6) {
		logger(LOG_ERR, _("Got bad %s from %s (%s)"), "ADD_EDGE", c->name,
			   c->hostname);
		return false;
	}

	/* Check if names are valid */

	if(!check_id(from_name)) {
		logger(LOG_ERR, _("Got bad %s from %s (%s): %s"), "ADD_EDGE", c->name,
			   c->hostname, _("invalid name"));
		return false;
	}

	if(!check_id(to_name)) {
		logger(LOG_ERR, _("Got bad %s from %s (%s): %s"), "ADD_EDGE", c->name,
			   c->hostname, _("invalid name"));
		return false;
	}

	if(seen_request(c->buffer))
		return true;

	/* Lookup nodes */

	from = lookup_node(from_name);

	if(!from) {
		from = new_node();
		from->name = xstrdup(from_name);
		node_add(from);
	}

	to = lookup_node(to_name);

	if(!to) {
		to = new_node();
		to->name = xstrdup(to_name);
		node_add(to);
	}

	if(c->status.opaque && from != myself && from != c->node && to != myself && to != c->node)
		return false;

	/* Convert addresses */

	address = str2sockaddr(to_address, to_port);

	/* Check if edge already exists */

	e = lookup_edge(from, to);

	if(e) {
		if(e->weight != weight || e->options != options || sockaddrcmp(&e->address, &address)) {
			if(from == myself) {
				ifdebug(PROTOCOL) logger(LOG_WARNING, _("Got %s from %s (%s) for ourself which does not match existing entry"),
						   "ADD_EDGE", c->name, c->hostname);
				send_add_edge(c, e);
				return true;
			} else {
				ifdebug(PROTOCOL) logger(LOG_WARNING, _("Got %s from %s (%s) which does not match existing entry"),
						   "ADD_EDGE", c->name, c->hostname);
				edge_del(e);
				graph();
			}
		} else
			return true;
	} else if(from == myself) {
		ifdebug(PROTOCOL) logger(LOG_WARNING, _("Got %s from %s (%s) for ourself which does not exist"),
				   "ADD_EDGE", c->name, c->hostname);
		e = new_edge();
		e->from = from;
		e->to = to;
		send_del_edge(c, e);
		free_edge(e);
		return true;
	}

	e = new_edge();
	e->from = from;
	e->to = to;
	e->address = address;
	e->options = options;
	e->weight = weight;
	edge_add(e);

	/* Tell the rest about the new edge */

	if(!c->status.opaque)
		forward_request(c);

	/* Run MST before or after we tell the rest? */

	graph();

	return true;
}

bool send_del_edge(connection_t *c, const edge_t *e)
{
	cp();

	return send_request(c, "%d %lx %s %s", DEL_EDGE, random(),
						e->from->name, e->to->name);
}

bool del_edge_h(connection_t *c)
{
	edge_t *e;
	char from_name[MAX_STRING_SIZE];
	char to_name[MAX_STRING_SIZE];
	node_t *from, *to;

	cp();

	if(sscanf(c->buffer, "%*d %*x "MAX_STRING" "MAX_STRING, from_name, to_name) != 2) {
		logger(LOG_ERR, _("Got bad %s from %s (%s)"), "DEL_EDGE", c->name,
			   c->hostname);
		return false;
	}

	/* Check if names are valid */

	if(!check_id(from_name)) {
		logger(LOG_ERR, _("Got bad %s from %s (%s): %s"), "DEL_EDGE", c->name,
			   c->hostname, _("invalid name"));
		return false;
	}

	if(!check_id(to_name)) {
		logger(LOG_ERR, _("Got bad %s from %s (%s): %s"), "DEL_EDGE", c->name,
			   c->hostname, _("invalid name"));
		return false;
	}

	if(seen_request(c->buffer))
		return true;

	/* Lookup nodes */

	from = lookup_node(from_name);

	if(!from) {
		ifdebug(PROTOCOL) logger(LOG_ERR, _("Got %s from %s (%s) which does not appear in the edge tree"),
				   "DEL_EDGE", c->name, c->hostname);
		return true;
	}

	to = lookup_node(to_name);

	if(!to) {
		ifdebug(PROTOCOL) logger(LOG_ERR, _("Got %s from %s (%s) which does not appear in the edge tree"),
				   "DEL_EDGE", c->name, c->hostname);
		return true;
	}

	if(c->status.opaque && from != myself && from != c->node && to != myself && to != c->node)
		return false;

	/* Check if edge exists */

	e = lookup_edge(from, to);

	if(!e) {
		ifdebug(PROTOCOL) logger(LOG_WARNING, _("Got %s from %s (%s) which does not appear in the edge tree"),
				   "DEL_EDGE", c->name, c->hostname);
		return true;
	}

	if(e->from == myself) {
		ifdebug(PROTOCOL) logger(LOG_WARNING, _("Got %s from %s (%s) for ourself"),
				   "DEL_EDGE", c->name, c->hostname);
		send_add_edge(c, e);	/* Send back a correction */
		return true;
	}

	/* Tell the rest about the deleted edge */

	if(!c->status.opaque)
		forward_request(c);

	/* Delete the edge */

	edge_del(e);

	/* Run MST before or after we tell the rest? */

	graph();

	/* If the node is not reachable anymore but we remember it had an edge to us, clean it up */

	if(!to->status.reachable) {
		e = lookup_edge(to, myself);
		if(e) {
			send_del_edge(broadcast, e);
			edge_del(e);
		}
	}

	return true;
}
