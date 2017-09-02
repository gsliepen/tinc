/*
    net.c -- most of the network code
    Copyright (C) 1998-2005 Ivo Timmermans,
                  2000-2017 Guus Sliepen <guus@tinc-vpn.org>
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

#include "autoconnect.h"
#include "conf.h"
#include "connection.h"
#include "device.h"
#include "graph.h"
#include "logger.h"
#include "meta.h"
#include "names.h"
#include "net.h"
#include "netutl.h"
#include "protocol.h"
#include "subnet.h"
#include "utils.h"
#include "xalloc.h"

int contradicting_add_edge = 0;
int contradicting_del_edge = 0;
static int sleeptime = 10;
time_t last_config_check = 0;
static timeout_t pingtimer;
static timeout_t periodictimer;
static struct timeval last_periodic_run_time;

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

			if(!autoconnect && (!strictsubnets || !n->subnet_tree->head))
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

	if(c->node) {
		if(c->node->connection == c)
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
	}

	outgoing_t *outgoing = c->outgoing;
	connection_del(c);

	/* Check if this was our outgoing connection */

	if(outgoing)
		do_outgoing_connection(outgoing);

#ifndef HAVE_MINGW
	/* Clean up dead proxy processes */

	while(waitpid(-1, NULL, WNOHANG) > 0);
#endif
}

/*
  Check if the other end is active.
  If we have sent packets, but didn't receive any,
  then possibly the other end is dead. We send a
  PING request over the meta connection. If the other
  end does not reply in time, we consider them dead
  and close the connection.
*/
static void timeout_handler(void *data) {

	bool close_all_connections = false;

	/*
		 timeout_handler will start after 30 seconds from start of tincd
		 hold information about the elapsed time since last time the handler
		 has been run
	*/
	long sleep_time = now.tv_sec - last_periodic_run_time.tv_sec;
	/*
		 It seems that finding sane default value is harder than expected
		 Since we send every second a UDP packet to make holepunching work
		 And default UDP state expire on firewalls is between 15-30 seconds
		 we drop all connections after 60 Seconds - UDPDiscoveryTimeout=30
		 by default
	*/
	if (sleep_time > 2 * udp_discovery_timeout) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Awaking from dead after %ld seconds of sleep", sleep_time);
		/*
			Do not send any packets to tinc after we wake up.
			The other node probably closed our connection but we still
			are holding context information to them. This may happen on
			laptops or any other hardware which can be suspended for some time.
			Sending any data to node that wasn't expecting it will produce
			annoying and misleading errors on the other side about failed signature
			verification and or about missing sptps context
		*/
		close_all_connections = true;
	}
	last_periodic_run_time = now;

	for list_each(connection_t, c, connection_list) {
		// control connections (eg. tinc ctl) do not have any timeout
		if(c->status.control)
			continue;

		if(close_all_connections) {
			logger(DEBUG_ALWAYS, LOG_ERR, "Forcing connection close after sleep time %s (%s)", c->name, c->hostname);
			terminate_connection(c, c->edge);
			continue;
		}

		// Bail out early if we haven't reached the ping timeout for this node yet
		if(c->last_ping_time + pingtimeout > now.tv_sec)
			continue;

		// timeout during connection establishing
		if(!c->edge) {
			if(c->status.connecting)
				logger(DEBUG_CONNECTIONS, LOG_WARNING, "Timeout while connecting to %s (%s)", c->name, c->hostname);
			else
				logger(DEBUG_CONNECTIONS, LOG_WARNING, "Timeout from %s (%s) during authentication", c->name, c->hostname);

			terminate_connection(c, c->edge);
			continue;
		}

		// helps in UDP holepunching
		try_tx(c->node, false);

		// timeout during ping
		if(c->status.pinged) {
			logger(DEBUG_CONNECTIONS, LOG_INFO, "%s (%s) didn't respond to PING in %ld seconds", c->name, c->hostname, (long)(now.tv_sec - c->last_ping_time));
			terminate_connection(c, c->edge);
			continue;
		}

		// check whether we need to send a new ping
		if(c->last_ping_time + pinginterval <= now.tv_sec)
			send_ping(c);
	}

	timeout_set(data, &(struct timeval){1, rand() % 100000});
}

static void periodic_handler(void *data) {
	/* Check if there are too many contradicting ADD_EDGE and DEL_EDGE messages.
	   This usually only happens when another node has the same Name as this node.
	   If so, sleep for a short while to prevent a storm of contradicting messages.
	*/

	if(contradicting_del_edge > 100 && contradicting_add_edge > 100) {
		logger(DEBUG_ALWAYS, LOG_WARNING, "Possible node with same Name as us! Sleeping %d seconds.", sleeptime);
		nanosleep(&(struct timespec){sleeptime, 0}, NULL);
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

	/* If AutoConnect is set, check if we need to make or break connections. */

	if(autoconnect && node_tree->count > 1)
		do_autoconnect();

	timeout_set(data, &(struct timeval){5, rand() % 100000});
}

void handle_meta_connection_data(connection_t *c) {
	if (!receive_meta(c)) {
		terminate_connection(c, c->edge);
		return;
	}
}

#ifndef HAVE_MINGW
static void sigterm_handler(void *data) {
	logger(DEBUG_ALWAYS, LOG_NOTICE, "Got %s signal", strsignal(((signal_t *)data)->signum));
	event_exit();
}

static void sighup_handler(void *data) {
	logger(DEBUG_ALWAYS, LOG_NOTICE, "Got %s signal", strsignal(((signal_t *)data)->signum));
	reopenlogger();
	if(reload_configuration())
		exit(1);
}

static void sigalrm_handler(void *data) {
	logger(DEBUG_ALWAYS, LOG_NOTICE, "Got %s signal", strsignal(((signal_t *)data)->signum));
	retry();
}
#endif

int reload_configuration(void) {
	char fname[PATH_MAX];

	/* Reread our own configuration file */

	exit_configuration(&config_tree);
	init_configuration(&config_tree);

	if(!read_server_config()) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Unable to reread configuration file.");
		return EINVAL;
	}

	read_config_options(config_tree, NULL);

	snprintf(fname, sizeof fname, "%s" SLASH "hosts" SLASH "%s", confbase, myself->name);
	read_config_file(config_tree, fname);

	/* Parse some options that are allowed to be changed while tinc is running */

	setup_myself_reloadable();

	/* If StrictSubnet is set, expire deleted Subnets and read new ones in */

	if(strictsubnets) {
		for splay_each(subnet_t, subnet, subnet_tree)
			if (subnet->owner)
				subnet->expires = 1;
	}

	for splay_each(node_t, n, node_tree)
		n->status.has_address = false;

	load_all_nodes();

	if(strictsubnets) {
		for splay_each(subnet_t, subnet, subnet_tree) {
			if (!subnet->owner)
				continue;
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

		snprintf(fname, sizeof fname, "%s" SLASH "hosts" SLASH "%s", confbase, c->name);
		struct stat s;
		if(stat(fname, &s) || s.st_mtime > last_config_check) {
			logger(DEBUG_CONNECTIONS, LOG_INFO, "Host config file of %s has been changed", c->name);
			terminate_connection(c, c->edge);
		}
	}

	last_config_check = now.tv_sec;

	return 0;
}

void retry(void) {
	/* Reset the reconnection timers for all outgoing connections */
	for list_each(outgoing_t, outgoing, outgoing_list) {
		outgoing->timeout = 0;
		if(outgoing->ev.cb)
			timeout_set(&outgoing->ev, &(struct timeval){0, 0});
	}

	/* Check for outgoing connections that are in progress, and reset their ping timers */
	for list_each(connection_t, c, connection_list) {
		if(c->outgoing && !c->node)
			c->last_ping_time = 0;
	}

	/* Kick the ping timeout handler */
	timeout_set(&pingtimer, &(struct timeval){0, 0});
}

/*
  this is where it all happens...
*/
int main_loop(void) {
	last_periodic_run_time = now;
	timeout_add(&pingtimer, timeout_handler, &pingtimer, &(struct timeval){pingtimeout, rand() % 100000});
	timeout_add(&periodictimer, periodic_handler, &periodictimer, &(struct timeval){0, 0});

#ifndef HAVE_MINGW
	signal_t sighup = {0};
	signal_t sigterm = {0};
	signal_t sigquit = {0};
	signal_t sigint = {0};
	signal_t sigalrm = {0};

	signal_add(&sighup, sighup_handler, &sighup, SIGHUP);
	signal_add(&sigterm, sigterm_handler, &sigterm, SIGTERM);
	signal_add(&sigquit, sigterm_handler, &sigquit, SIGQUIT);
	signal_add(&sigint, sigterm_handler, &sigint, SIGINT);
	signal_add(&sigalrm, sigalrm_handler, &sigalrm, SIGALRM);
#endif

	if(!event_loop()) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Error while waiting for input: %s", sockstrerror(sockerrno));
		return 1;
	}

#ifndef HAVE_MINGW
	signal_del(&sighup);
	signal_del(&sigterm);
	signal_del(&sigquit);
	signal_del(&sigint);
	signal_del(&sigalrm);
#endif

	timeout_del(&periodictimer);
	timeout_del(&pingtimer);

	return 0;
}
