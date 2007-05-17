/*
    net.c -- most of the network code
    Copyright (C) 1998-2005 Ivo Timmermans,
                  2000-2006 Guus Sliepen <guus@tinc-vpn.org>

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

    $Id$
*/

#include "system.h"

#include <openssl/rand.h>

#include "utils.h"
#include "avl_tree.h"
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
#include "route.h"
#include "subnet.h"
#include "xalloc.h"

volatile bool running = false;

time_t now = 0;

/* Purge edges and subnets of unreachable nodes. Use carefully. */

static void purge(void)
{
	avl_node_t *nnode, *nnext, *enode, *enext, *snode, *snext;
	node_t *n;
	edge_t *e;
	subnet_t *s;

	cp();

	ifdebug(PROTOCOL) logger(LOG_DEBUG, _("Purging unreachable nodes"));

	/* Remove all edges and subnets owned by unreachable nodes. */

	for(nnode = node_tree->head; nnode; nnode = nnext) {
		nnext = nnode->next;
		n = nnode->data;

		if(!n->status.reachable) {
			ifdebug(SCARY_THINGS) logger(LOG_DEBUG, _("Purging node %s (%s)"), n->name,
					   n->hostname);

			for(snode = n->subnet_tree->head; snode; snode = snext) {
				snext = snode->next;
				s = snode->data;
				if(!tunnelserver)
					send_del_subnet(broadcast, s);
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

			if(!enode)
				node_del(n);
		}
	}
}

/*
  put all file descriptors into events
  While we're at it, purge stuf that needs to be removed.
*/
static int build_fdset(void)
{
	avl_node_t *node, *next;
	connection_t *c;
	int i, max = 0;

	cp();

	for(node = connection_tree->head; node; node = next) {
		next = node->next;
		c = node->data;

		if(c->status.remove) {
			connection_del(c);
			if(!connection_tree->head)
				purge();
		}
	}

	return 0;
}

/*
  Terminate a connection:
  - Close the socket
  - Remove associated edge and tell other connections about it if report = true
  - Check if we need to retry making an outgoing connection
  - Deactivate the host
*/
void terminate_connection(connection_t *c, bool report)
{
	cp();

	if(c->status.remove)
		return;

	ifdebug(CONNECTIONS) logger(LOG_NOTICE, _("Closing connection with %s (%s)"),
			   c->name, c->hostname);

	c->status.remove = true;
	c->status.active = false;

	if(c->node)
		c->node->connection = NULL;

	if(c->socket)
		closesocket(c->socket);

	event_del(&c->ev);

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

	if(c->outgoing) {
		retry_outgoing(c->outgoing);
		c->outgoing = NULL;
	}

	free(c->outbuf);
	c->outbuf = NULL;
	c->outbuflen = 0;
	c->outbufsize = 0;
	c->outbufstart = 0;
}

/*
  Check if the other end is active.
  If we have sent packets, but didn't receive any,
  then possibly the other end is dead. We send a
  PING request over the meta connection. If the other
  end does not reply in time, we consider them dead
  and close the connection.
*/
static void check_dead_connections(void)
{
	avl_node_t *node, *next;
	connection_t *c;

	cp();

	for(node = connection_tree->head; node; node = next) {
		next = node->next;
		c = node->data;

		if(c->last_ping_time + pingtimeout < now) {
			if(c->status.active) {
				if(c->status.pinged) {
					ifdebug(CONNECTIONS) logger(LOG_INFO, _("%s (%s) didn't respond to PING in %ld seconds"),
							   c->name, c->hostname, now - c->last_ping_time);
					c->status.timeout = true;
					terminate_connection(c, true);
				} else if(c->last_ping_time + pinginterval < now) {
					send_ping(c);
				}
			} else {
				if(c->status.remove) {
					logger(LOG_WARNING, _("Old connection_t for %s (%s) status %04x still lingering, deleting..."),
						   c->name, c->hostname, c->status.value);
					connection_del(c);
					continue;
				}
				ifdebug(CONNECTIONS) logger(LOG_WARNING, _("Timeout from %s (%s) during authentication"),
						   c->name, c->hostname);
				if(c->status.connecting) {
					c->status.connecting = false;
					closesocket(c->socket);
					do_outgoing_connection(c);
				} else {
					terminate_connection(c, false);
				}
			}
		}

		if(c->outbuflen > 0 && c->last_flushed_time + pingtimeout < now) {
			if(c->status.active) {
				ifdebug(CONNECTIONS) logger(LOG_INFO,
						_("%s (%s) could not flush for %ld seconds (%d bytes remaining)"),
						c->name, c->hostname, now - c->last_flushed_time, c->outbuflen);
				c->status.timeout = true;
				terminate_connection(c, true);
			}
		}
	}
}

void handle_meta_connection_data(int fd, short events, void *data)
{
	connection_t *c = data;
	int result;
	socklen_t len = sizeof(result);

	if (c->status.remove)
		return;

	if(c->status.connecting) {
		getsockopt(c->socket, SOL_SOCKET, SO_ERROR, &result, &len);

		if(!result)
			finish_connecting(c);
		else {
			ifdebug(CONNECTIONS) logger(LOG_DEBUG,
					   _("Error while connecting to %s (%s): %s"),
					   c->name, c->hostname, strerror(result));
			c->status.connecting = false;
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

static void dummy(int a, short b, void *c)
{
}

static void sigterm_handler(int signal, short events, void *data) {
	logger(LOG_NOTICE, _("Got %s signal"), strsignal(signal));
	running = false;
	event_loopexit(NULL);
}

static void sigint_handler(int signal, short events, void *data) {
	static int saved_debug_level = -1;

	logger(LOG_NOTICE, _("Got %s signal"), strsignal(signal));

	if(saved_debug_level != -1) {
		logger(LOG_NOTICE, _("Reverting to old debug level (%d)"),
			saved_debug_level);
		debug_level = saved_debug_level;
		saved_debug_level = -1;
	} else {
		logger(LOG_NOTICE,
			_("Temporarily setting debug level to 5.  Kill me with SIGINT again to go back to level %d."),
			debug_level);
		saved_debug_level = debug_level;
		debug_level = 5;
	}
}

static void sigusr1_handler(int signal, short events, void *data) {
	logger(LOG_NOTICE, _("Got %s signal"), strsignal(signal));
	dump_connections();
}

static void sigusr2_handler(int signal, short events, void *data) {
	logger(LOG_NOTICE, _("Got %s signal"), strsignal(signal));
	dump_device_stats();
	dump_nodes();
	dump_edges();
	dump_subnets();
}

static void sigwinch_handler(int signal, short events, void *data) {
	logger(LOG_NOTICE, _("Got %s signal"), strsignal(signal));
	purge();
}

static void sighup_handler(int signal, short events, void *data) {
	connection_t *c;
	avl_node_t *node;
	char *fname;
	struct stat s;
	static time_t last_config_check = 0;
	
	logger(LOG_NOTICE, _("Got %s signal"), strsignal(signal));

	/* Reread our own configuration file */

	exit_configuration(&config_tree);
	init_configuration(&config_tree);

	if(!read_server_config()) {
		logger(LOG_ERR, _("Unable to reread configuration file, exitting."));
		event_loopexit(NULL);
		return;
	}

	/* Close connections to hosts that have a changed or deleted host config file */
	
	for(node = connection_tree->head; node; node = node->next) {
		c = node->data;
		
		if(c->outgoing) {
			free(c->outgoing->name);
			if(c->outgoing->ai)
				freeaddrinfo(c->outgoing->ai);
			free(c->outgoing);
			c->outgoing = NULL;
		}
		
		asprintf(&fname, "%s/hosts/%s", confbase, c->name);
		if(stat(fname, &s) || s.st_mtime > last_config_check)
			terminate_connection(c, c->status.active);
		free(fname);
	}

	last_config_check = time(NULL);

	/* Try to make outgoing connections */
	
	try_outgoing_connections();
}

static void sigalrm_handler(int signal, short events, void *data) {
	logger(LOG_NOTICE, _("Got %s signal"), strsignal(signal));

	connection_t *c;
	avl_node_t *node;

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
int main_loop(void)
{
	struct timeval tv;
	int r;
	time_t last_ping_check;
	struct event timeout;
	struct event sighup_event;
	struct event sigint_event;
	struct event sigterm_event;
	struct event sigquit_event;
	struct event sigusr1_event;
	struct event sigusr2_event;
	struct event sigwinch_event;
	struct event sigalrm_event;

	cp();

	signal_set(&sighup_event, SIGHUP, sighup_handler, NULL);
	signal_add(&sighup_event, NULL);
	signal_set(&sigint_event, SIGINT, sigint_handler, NULL);
	signal_add(&sigint_event, NULL);
	signal_set(&sigterm_event, SIGTERM, sigterm_handler, NULL);
	signal_add(&sigterm_event, NULL);
	signal_set(&sigquit_event, SIGQUIT, sigterm_handler, NULL);
	signal_add(&sigquit_event, NULL);
	signal_set(&sigusr1_event, SIGUSR1, sigusr1_handler, NULL);
	signal_add(&sigusr1_event, NULL);
	signal_set(&sigusr2_event, SIGUSR2, sigusr2_handler, NULL);
	signal_add(&sigusr2_event, NULL);
	signal_set(&sigwinch_event, SIGWINCH, sigwinch_handler, NULL);
	signal_add(&sigwinch_event, NULL);
	signal_set(&sigalrm_event, SIGALRM, sigalrm_handler, NULL);
	signal_add(&sigalrm_event, NULL);

	last_ping_check = now;
	
	srand(now);

	running = true;

	while(running) {
		now = time(NULL);

	//	tv.tv_sec = 1 + (rand() & 7);	/* Approx. 5 seconds, randomized to prevent global synchronisation effects */
		tv.tv_sec = 1;
		tv.tv_usec = 0;

		/* XXX: libevent transition: old timeout code in this loop */
		timeout_set(&timeout, dummy, NULL);
		timeout_add(&timeout, &tv);

		r = build_fdset();
		if(r < 0) {
			logger(LOG_ERR, _("Error building fdset: %s"), strerror(errno));
			cp_trace();
			dump_connections();
			return 1;
		}

		r = event_loop(EVLOOP_ONCE);
		now = time(NULL);
		if(r < 0) {
			logger(LOG_ERR, _("Error while waiting for input: %s"),
				   strerror(errno));
			cp_trace();
			dump_connections();
			return 1;
		}

		/* XXX: more libevent transition */
		timeout_del(&timeout);

		/* Let's check if everybody is still alive */

		if(last_ping_check + pingtimeout < now) {
			check_dead_connections();
			last_ping_check = now;

			if(routing_mode == RMODE_SWITCH)
				age_subnets();

			/* Should we regenerate our key? */

			if(keyexpires < now) {
				ifdebug(STATUS) logger(LOG_INFO, _("Regenerating symmetric key"));

				RAND_pseudo_bytes((unsigned char *)myself->key, myself->keylength);
				if(myself->cipher)
					EVP_DecryptInit_ex(&packet_ctx, myself->cipher, NULL, (unsigned char *)myself->key, (unsigned char *)myself->key + myself->cipher->key_len);
				send_key_changed(broadcast, myself);
				keyexpires = now + keylifetime;
			}
		}
	}

	signal_del(&sighup_event);
	signal_del(&sigint_event);
	signal_del(&sigterm_event);
	signal_del(&sigquit_event);
	signal_del(&sigusr1_event);
	signal_del(&sigusr2_event);
	signal_del(&sigwinch_event);
	signal_del(&sigalrm_event);

	return 0;
}
