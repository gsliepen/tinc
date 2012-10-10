/*
    net.c -- most of the network code
    Copyright (C) 1998-2005 Ivo Timmermans,
                  2000-2012 Guus Sliepen <guus@tinc-vpn.org>
                  2006      Scott Lamb <slamb@slamb.org>
                  2011      Loïc Grenié <loic.grenie@gmail.com>

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

#include "utils.h"
#include "conf.h"
#include "connection.h"
#include "device.h"
#include "graph.h"
#include "logger.h"
#include "meta.h"
#include "net.h"
#include "netutl.h"
#include "process.h"
#include "protocol.h"
#include "subnet.h"
#include "xalloc.h"

int contradicting_add_edge = 0;
int contradicting_del_edge = 0;
static int sleeptime = 10;
time_t last_config_check = 0;

/* Purge edges and subnets of unreachable nodes. Use carefully. */

void purge(void) {
	logger(DEBUG_PROTOCOL, LOG_DEBUG, "Purging unreachable nodes");

	/* Remove all edges and subnets owned by unreachable nodes. */

	for splay_each(node_t, n, node_tree) {
		if(!n->status.reachable) {
			logger(DEBUG_SCARY_THINGS, LOG_DEBUG, "Purging node %s (%s)", n->name, n->hostname);

			for splay_each(subnet_t, s, n->subnet_tree) {
				send_del_subnet(everyone, s);
				if(!strictsubnets)
					subnet_del(n, s);
			}

			for splay_each(edge_t, e, n->edge_tree) {
				if(!tunnelserver)
					send_del_edge(everyone, e);
				edge_del(e);
			}
		}
	}

	/* Check if anyone else claims to have an edge to an unreachable node. If not, delete node. */

	for splay_each(node_t, n, node_tree) {
		if(!n->status.reachable) {
			for splay_each(edge_t, e, edge_weight_tree)
				if(e->to == n)
					return;

			if(!strictsubnets || !n->subnet_tree->head)
				/* in strictsubnets mode do not delete nodes with subnets */
				node_del(n);
		}
	}
}

/*
  Terminate a connection:
  - Mark it as inactive
  - Remove the edge representing this connection
  - Kill it with fire
  - Check if we need to retry making an outgoing connection
*/
void terminate_connection(connection_t *c, bool report) {
	logger(DEBUG_CONNECTIONS, LOG_NOTICE, "Closing connection with %s (%s)", c->name, c->hostname);

	c->status.active = false;

	if(c->node && c->node->connection == c)
		c->node->connection = NULL;

	if(c->edge) {
		if(report && !tunnelserver)
			send_del_edge(everyone, c->edge);

		edge_del(c->edge);
		c->edge = NULL;

		/* Run MST and SSSP algorithms */

		graph();

		/* If the node is not reachable anymore but we remember it had an edge to us, clean it up */

		if(report && !c->node->status.reachable) {
			edge_t *e;
			e = lookup_edge(c->node, myself);
			if(e) {
				if(!tunnelserver)
					send_del_edge(everyone, e);
				edge_del(e);
			}
		}
	}

	outgoing_t *outgoing = c->outgoing;
	connection_del(c);

	/* Check if this was our outgoing connection */

	if(outgoing)
		do_outgoing_connection(outgoing);
}

/*
  Check if the other end is active.
  If we have sent packets, but didn't receive any,
  then possibly the other end is dead. We send a
  PING request over the meta connection. If the other
  end does not reply in time, we consider them dead
  and close the connection.
*/
static void timeout_handler(int fd, short events, void *event) {
	time_t now = time(NULL);

	for list_each(connection_t, c, connection_list) {
		if(c->status.control)
			continue;

		if(c->last_ping_time + pingtimeout <= now) {
			if(c->status.active) {
				if(c->status.pinged) {
					logger(DEBUG_CONNECTIONS, LOG_INFO, "%s (%s) didn't respond to PING in %ld seconds", c->name, c->hostname, (long)now - c->last_ping_time);
				} else if(c->last_ping_time + pinginterval <= now) {
					send_ping(c);
					continue;
				} else {
					continue;
				}
			} else {
				if(c->status.connecting)
					logger(DEBUG_CONNECTIONS, LOG_WARNING, "Timeout while connecting to %s (%s)", c->name, c->hostname);
				else
					logger(DEBUG_CONNECTIONS, LOG_WARNING, "Timeout from %s (%s) during authentication", c->name, c->hostname);
			}
			terminate_connection(c, c->status.active);
		}
	}

	if(contradicting_del_edge > 100 && contradicting_add_edge > 100) {
		logger(DEBUG_ALWAYS, LOG_WARNING, "Possible node with same Name as us! Sleeping %d seconds.", sleeptime);
		usleep(sleeptime * 1000000LL);
		sleeptime *= 2;
		if(sleeptime < 0)
			sleeptime = 3600;
	} else {
		sleeptime /= 2;
		if(sleeptime < 10)
			sleeptime = 10;
	}

	contradicting_add_edge = 0;
	contradicting_del_edge = 0;

	event_add(event, &(struct timeval){pingtimeout, 0});
}

void handle_meta_connection_data(int fd, short events, void *data) {
	connection_t *c = data;
	int result;
	socklen_t len = sizeof result;

	if(c->status.connecting) {
		c->status.connecting = false;

		getsockopt(c->socket, SOL_SOCKET, SO_ERROR, &result, &len);

		if(!result)
			finish_connecting(c);
		else {
			logger(DEBUG_CONNECTIONS, LOG_DEBUG, "Error while connecting to %s (%s): %s", c->name, c->hostname, sockstrerror(result));
			terminate_connection(c, false);
			return;
		}
	}

	if (!receive_meta(c)) {
		terminate_connection(c, c->status.active);
		return;
	}
}

static void sigterm_handler(int signal, short events, void *data) {
	logger(DEBUG_ALWAYS, LOG_NOTICE, "Got %s signal", strsignal(signal));
	event_loopexit(NULL);
}

static void sighup_handler(int signal, short events, void *data) {
	logger(DEBUG_ALWAYS, LOG_NOTICE, "Got %s signal", strsignal(signal));
	reopenlogger();
	reload_configuration();
}

static void sigalrm_handler(int signal, short events, void *data) {
	logger(DEBUG_ALWAYS, LOG_NOTICE, "Got %s signal", strsignal(signal));
	retry();
}

int reload_configuration(void) {
	char *fname;

	/* Reread our own configuration file */

	exit_configuration(&config_tree);
	init_configuration(&config_tree);

	if(!read_server_config()) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Unable to reread configuration file, exitting.");
		event_loopexit(NULL);
		return EINVAL;
	}

	read_config_options(config_tree, NULL);

	xasprintf(&fname, "%s" SLASH "hosts" SLASH "%s", confbase, myself->name);
	read_config_file(config_tree, fname);
	free(fname);

	/* Parse some options that are allowed to be changed while tinc is running */

	setup_myself_reloadable();

	/* If StrictSubnet is set, expire deleted Subnets and read new ones in */

	if(strictsubnets) {
		for splay_each(subnet_t, subnet, subnet_tree)
			subnet->expires = 1;

		load_all_subnets();

		for splay_each(subnet_t, subnet, subnet_tree) {
			if(subnet->expires == 1) {
				send_del_subnet(everyone, subnet);
				if(subnet->owner->status.reachable)
					subnet_update(subnet->owner, subnet, false);
				subnet_del(subnet->owner, subnet);
			} else if(subnet->expires == -1) {
				subnet->expires = 0;
			} else {
				send_add_subnet(everyone, subnet);
				if(subnet->owner->status.reachable)
					subnet_update(subnet->owner, subnet, true);
			}
		}
	} else { /* Only read our own subnets back in */
		for splay_each(subnet_t, subnet, myself->subnet_tree)
			if(!subnet->expires)
				subnet->expires = 1;

		config_t *cfg = lookup_config(config_tree, "Subnet");

		while(cfg) {
			subnet_t *subnet, *s2;

			if(!get_config_subnet(cfg, &subnet))
				continue;

			if((s2 = lookup_subnet(myself, subnet))) {
				if(s2->expires == 1)
					s2->expires = 0;

				free_subnet(subnet);
			} else {
				subnet_add(myself, subnet);
				send_add_subnet(everyone, subnet);
				subnet_update(myself, subnet, true);
			}

			cfg = lookup_config_next(config_tree, cfg);
		}

		for splay_each(subnet_t, subnet, myself->subnet_tree) {
			if(subnet->expires == 1) {
				send_del_subnet(everyone, subnet);
				subnet_update(myself, subnet, false);
				subnet_del(myself, subnet);
			}
		}
	}

	/* Try to make outgoing connections */

	try_outgoing_connections();

	/* Close connections to hosts that have a changed or deleted host config file */

	for list_each(connection_t, c, connection_list) {
		if(c->status.control)
			continue;

		xasprintf(&fname, "%s" SLASH "hosts" SLASH "%s", confbase, c->name);
		struct stat s;
		if(stat(fname, &s) || s.st_mtime > last_config_check) {
			logger(DEBUG_CONNECTIONS, LOG_INFO, "Host config file of %s has been changed", c->name);
			terminate_connection(c, c->status.active);
		}
		free(fname);
	}

	last_config_check = time(NULL);

	return 0;
}

void retry(void) {
	for list_each(connection_t, c, connection_list) {
		if(c->outgoing && !c->node) {
			if(timeout_initialized(&c->outgoing->ev))
				event_del(&c->outgoing->ev);
			if(c->status.connecting)
				close(c->socket);
			c->outgoing->timeout = 0;
			terminate_connection(c, c->status.active);
		}
	}
}

/*
  this is where it all happens...
*/
int main_loop(void) {
	struct event timeout_event;

	timeout_set(&timeout_event, timeout_handler, &timeout_event);
	event_add(&timeout_event, &(struct timeval){pingtimeout, 0});

#ifndef HAVE_MINGW
	struct event sighup_event;
	struct event sigterm_event;
	struct event sigquit_event;
	struct event sigalrm_event;

	signal_set(&sighup_event, SIGHUP, sighup_handler, NULL);
	signal_add(&sighup_event, NULL);
	signal_set(&sigterm_event, SIGTERM, sigterm_handler, NULL);
	signal_add(&sigterm_event, NULL);
	signal_set(&sigquit_event, SIGQUIT, sigterm_handler, NULL);
	signal_add(&sigquit_event, NULL);
	signal_set(&sigalrm_event, SIGALRM, sigalrm_handler, NULL);
	signal_add(&sigalrm_event, NULL);
#endif

	if(event_loop(0) < 0) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Error while waiting for input: %s", strerror(errno));
		return 1;
	}

#ifndef HAVE_MINGW
	signal_del(&sighup_event);
	signal_del(&sigterm_event);
	signal_del(&sigquit_event);
	signal_del(&sigalrm_event);
#endif

	event_del(&timeout_event);

	return 0;
}
