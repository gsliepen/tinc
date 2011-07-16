/*
    net.c -- most of the network code
    Copyright (C) 1998-2005 Ivo Timmermans,
                  2000-2011 Guus Sliepen <guus@tinc-vpn.org>
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
#include "splay_tree.h"
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

/* Purge edges and subnets of unreachable nodes. Use carefully. */

void purge(void) {
	splay_node_t *nnode, *nnext, *enode, *enext, *snode, *snext;
	node_t *n;
	edge_t *e;
	subnet_t *s;

	ifdebug(PROTOCOL) logger(LOG_DEBUG, "Purging unreachable nodes");

	/* Remove all edges and subnets owned by unreachable nodes. */

	for(nnode = node_tree->head; nnode; nnode = nnext) {
		nnext = nnode->next;
		n = nnode->data;

		if(!n->status.reachable) {
			ifdebug(SCARY_THINGS) logger(LOG_DEBUG, "Purging node %s (%s)", n->name,
					   n->hostname);

			for(snode = n->subnet_tree->head; snode; snode = snext) {
				snext = snode->next;
				s = snode->data;
				send_del_subnet(broadcast, s);
				if(!strictsubnets)
					subnet_del(n, s);
			}

			for(enode = n->edge_tree->head; enode; enode = enext) {
				enext = enode->next;
				e = enode->data;
				if(!tunnelserver)
					send_del_edge(broadcast, e);
				edge_del(e);
			}
		}
	}

	/* Check if anyone else claims to have an edge to an unreachable node. If not, delete node. */

	for(nnode = node_tree->head; nnode; nnode = nnext) {
		nnext = nnode->next;
		n = nnode->data;

		if(!n->status.reachable) {
			for(enode = edge_weight_tree->head; enode; enode = enext) {
				enext = enode->next;
				e = enode->data;

				if(e->to == n)
					break;
			}

			if(!enode && (!strictsubnets || !n->subnet_tree->head))
				/* in strictsubnets mode do not delete nodes with subnets */
				node_del(n);
		}
	}
}

/*
  Terminate a connection:
  - Close the socket
  - Remove associated edge and tell other connections about it if report = true
  - Check if we need to retry making an outgoing connection
  - Deactivate the host
*/
void terminate_connection(connection_t *c, bool report) {
	ifdebug(CONNECTIONS) logger(LOG_NOTICE, "Closing connection with %s (%s)",
			   c->name, c->hostname);

	c->status.active = false;

	if(c->node)
		c->node->connection = NULL;

	if(c->edge) {
		if(report && !tunnelserver)
			send_del_edge(broadcast, c->edge);

		edge_del(c->edge);

		/* Run MST and SSSP algorithms */

		graph();

		/* If the node is not reachable anymore but we remember it had an edge to us, clean it up */

		if(report && !c->node->status.reachable) {
			edge_t *e;
			e = lookup_edge(c->node, myself);
			if(e) {
				if(!tunnelserver)
					send_del_edge(broadcast, e);
				edge_del(e);
			}
		}
	}

	/* Check if this was our outgoing connection */

	if(c->outgoing)
		retry_outgoing(c->outgoing);

	connection_del(c);
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
	splay_node_t *node, *next;
	connection_t *c;
	time_t now = time(NULL);

	for(node = connection_tree->head; node; node = next) {
		next = node->next;
		c = node->data;

		if(c->last_ping_time + pingtimeout <= now) {
			if(c->status.active) {
				if(c->status.pinged) {
					ifdebug(CONNECTIONS) logger(LOG_INFO, "%s (%s) didn't respond to PING in %ld seconds",
							   c->name, c->hostname, now - c->last_ping_time);
					terminate_connection(c, true);
					continue;
				} else if(c->last_ping_time + pinginterval <= now) {
					send_ping(c);
				}
			} else {
				if(c->status.connecting) {
					ifdebug(CONNECTIONS)
						logger(LOG_WARNING, "Timeout while connecting to %s (%s)", c->name, c->hostname);
					c->status.connecting = false;
					closesocket(c->socket);
					do_outgoing_connection(c);
				} else {
					ifdebug(CONNECTIONS) logger(LOG_WARNING, "Timeout from %s (%s) during authentication", c->name, c->hostname);
					terminate_connection(c, false);
					continue;
				}
			}
		}
	}

	if(contradicting_del_edge > 100 && contradicting_add_edge > 100) {
		logger(LOG_WARNING, "Possible node with same Name as us! Sleeping %d seconds.", sleeptime);
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
			ifdebug(CONNECTIONS) logger(LOG_DEBUG,
					   "Error while connecting to %s (%s): %s",
					   c->name, c->hostname, sockstrerror(result));
			closesocket(c->socket);
			do_outgoing_connection(c);
			return;
		}
	}

	if (!receive_meta(c)) {
		terminate_connection(c, c->status.active);
		return;
	}
}

static void sigterm_handler(int signal, short events, void *data) {
	logger(LOG_NOTICE, "Got %s signal", strsignal(signal));
	event_loopexit(NULL);
}

static void sighup_handler(int signal, short events, void *data) {
	logger(LOG_NOTICE, "Got %s signal", strsignal(signal));
	reopenlogger();
	reload_configuration();
}

static void sigalrm_handler(int signal, short events, void *data) {
	logger(LOG_NOTICE, "Got %s signal", strsignal(signal));
	retry();
}

int reload_configuration(void) {
	connection_t *c;
	splay_node_t *node, *next;
	char *fname;
	struct stat s;
	static time_t last_config_check = 0;

	/* Reread our own configuration file */

	exit_configuration(&config_tree);
	init_configuration(&config_tree);

	if(!read_server_config()) {
		logger(LOG_ERR, "Unable to reread configuration file, exitting.");
		event_loopexit(NULL);
		return EINVAL;
	}

	/* Close connections to hosts that have a changed or deleted host config file */
	
	for(node = connection_tree->head; node; node = next) {
		c = node->data;
		next = node->next;
		
		if(c->outgoing) {
			free(c->outgoing->name);
			if(c->outgoing->ai)
				freeaddrinfo(c->outgoing->ai);
			free(c->outgoing);
			c->outgoing = NULL;
		}
		
		xasprintf(&fname, "%s/hosts/%s", confbase, c->name);
		if(stat(fname, &s) || s.st_mtime > last_config_check)
			terminate_connection(c, c->status.active);
		free(fname);
	}

	last_config_check = time(NULL);

	/* If StrictSubnet is set, expire deleted Subnets and read new ones in */

	if(strictsubnets) {
		subnet_t *subnet;


		for(node = subnet_tree->head; node; node = node->next) {
			subnet = node->data;
			subnet->expires = 1;
		}

		load_all_subnets();

		for(node = subnet_tree->head; node; node = next) {
			next = node->next;
			subnet = node->data;
			if(subnet->expires == 1) {
				send_del_subnet(broadcast, subnet);
				if(subnet->owner->status.reachable)
					subnet_update(subnet->owner, subnet, false);
				subnet_del(subnet->owner, subnet);
			} else if(subnet->expires == -1) {
				subnet->expires = 0;
			} else {
				send_add_subnet(broadcast, subnet);
				if(subnet->owner->status.reachable)
					subnet_update(subnet->owner, subnet, true);
			}
		}
	}

	/* Try to make outgoing connections */
	
	try_outgoing_connections();

	return 0;
}

void retry(void) {
	connection_t *c;
	splay_node_t *node;

	for(node = connection_tree->head; node; node = node->next) {
		c = node->data;
		
		if(c->outgoing && !c->node) {
			if(timeout_initialized(&c->outgoing->ev))
				event_del(&c->outgoing->ev);
			if(c->status.connecting)
				close(c->socket);
			c->outgoing->timeout = 0;
			do_outgoing_connection(c);
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
		logger(LOG_ERR, "Error while waiting for input: %s", strerror(errno));
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
