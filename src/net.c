/*
    net.c -- most of the network code
    Copyright (C) 1998-2003 Ivo Timmermans <ivo@o2w.nl>,
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

    $Id: net.c,v 1.35.4.193 2003/07/23 22:17:31 guus Exp $
*/

#include "system.h"

#include <openssl/rand.h>

#include "utils.h"
#include "avl_tree.h"
#include "conf.h"
#include "connection.h"
#include "device.h"
#include "event.h"
#include "graph.h"
#include "logger.h"
#include "meta.h"
#include "net.h"
#include "netutl.h"
#include "process.h"
#include "protocol.h"
#include "route.h"
#include "subnet.h"

bool do_purge = false;

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

	for(nnode = node_tree->head; nnode; nnode = nnext) {
		nnext = nnode->next;
		n = (node_t *) nnode->data;

		if(!n->status.reachable) {
			ifdebug(SCARY_THINGS) logger(LOG_DEBUG, _("Purging node %s (%s)"), n->name,
					   n->hostname);

			for(snode = n->subnet_tree->head; snode; snode = snext) {
				snext = snode->next;
				s = (subnet_t *) snode->data;
				send_del_subnet(broadcast, s);
				subnet_del(n, s);
			}

			for(enode = n->edge_tree->head; enode; enode = enext) {
				enext = enode->next;
				e = (edge_t *) enode->data;
				send_del_edge(broadcast, e);
				edge_del(e);
			}

			node_del(n);
		}
	}
}

/*
  put all file descriptors in an fd_set array
  While we're at it, purge stuff that needs to be removed.
*/
static int build_fdset(fd_set * fs)
{
	avl_node_t *node, *next;
	connection_t *c;
	int i, max = 0;

	cp();

	FD_ZERO(fs);

	for(node = connection_tree->head; node; node = next) {
		next = node->next;
		c = (connection_t *) node->data;

		if(c->status.remove) {
			connection_del(c);
			if(!connection_tree->head)
				purge();
		} else {
			FD_SET(c->socket, fs);
			if(c->socket > max)
				max = c->socket;
		}
	}

	for(i = 0; i < listen_sockets; i++) {
		FD_SET(listen_socket[i].tcp, fs);
		if(listen_socket[i].tcp > max)
			max = listen_socket[i].tcp;
		FD_SET(listen_socket[i].udp, fs);
		if(listen_socket[i].udp > max)
			max = listen_socket[i].udp;
	}

	FD_SET(device_fd, fs);
	if(device_fd > max)
		max = device_fd;
	
	return max;
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
		close(c->socket);

	if(c->edge) {
		if(report)
			send_del_edge(broadcast, c->edge);

		edge_del(c->edge);

		/* Run MST and SSSP algorithms */

		graph();
	}

	/* Check if this was our outgoing connection */

	if(c->outgoing) {
		retry_outgoing(c->outgoing);
		c->outgoing = NULL;
	}
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
		c = (connection_t *) node->data;

		if(c->last_ping_time + pingtimeout < now) {
			if(c->status.active) {
				if(c->status.pinged) {
					ifdebug(CONNECTIONS) logger(LOG_INFO, _("%s (%s) didn't respond to PING"),
							   c->name, c->hostname);
					c->status.timeout = true;
					terminate_connection(c, true);
				} else {
					send_ping(c);
				}
			} else {
				if(c->status.remove) {
					logger(LOG_WARNING, _("Old connection_t for %s (%s) status %04x still lingering, deleting..."),
						   c->name, c->hostname, c->status);
					connection_del(c);
					continue;
				}
				ifdebug(CONNECTIONS) logger(LOG_WARNING, _("Timeout from %s (%s) during authentication"),
						   c->name, c->hostname);
				terminate_connection(c, false);
			}
		}
	}
}

/*
  check all connections to see if anything
  happened on their sockets
*/
static void check_network_activity(fd_set * f)
{
	connection_t *c;
	avl_node_t *node;
	int result, i;
	int len = sizeof(result);
	vpn_packet_t packet;

	cp();

	if(FD_ISSET(device_fd, f)) {
		if(read_packet(&packet))
			route_outgoing(&packet);
	}

	for(node = connection_tree->head; node; node = node->next) {
		c = (connection_t *) node->data;

		if(c->status.remove)
			continue;

		if(FD_ISSET(c->socket, f)) {
			if(c->status.connecting) {
				c->status.connecting = false;
				getsockopt(c->socket, SOL_SOCKET, SO_ERROR, &result, &len);

				if(!result)
					finish_connecting(c);
				else {
					ifdebug(CONNECTIONS) logger(LOG_DEBUG,
							   _("Error while connecting to %s (%s): %s"),
							   c->name, c->hostname, strerror(result));
					close(c->socket);
					do_outgoing_connection(c);
					continue;
				}
			}

			if(!receive_meta(c)) {
				terminate_connection(c, c->status.active);
				continue;
			}
		}
	}

	for(i = 0; i < listen_sockets; i++) {
		if(FD_ISSET(listen_socket[i].udp, f))
			handle_incoming_vpn_data(listen_socket[i].udp);

		if(FD_ISSET(listen_socket[i].tcp, f))
			handle_new_meta_connection(listen_socket[i].tcp);
	}
}

/*
  this is where it all happens...
*/
void main_loop(void)
{
	fd_set fset;
	struct timeval tv;
	int r, maxfd;
	time_t last_ping_check, last_config_check;
	event_t *event;

	cp();

	last_ping_check = now;
	last_config_check = now;
	srand(now);

	for(;;) {
		now = time(NULL);

		tv.tv_sec = 1 + (rand() & 7);	/* Approx. 5 seconds, randomized to prevent global synchronisation effects */
		tv.tv_usec = 0;

		maxfd = build_fdset(&fset);

		r = select(maxfd + 1, &fset, NULL, NULL, &tv);

		if(r < 0) {
			if(errno != EINTR && errno != EAGAIN) {
				logger(LOG_ERR, _("Error while waiting for input: %s"),
					   strerror(errno));
				cp_trace();
				dump_connections();
				return;
			}

			continue;
		}

		check_network_activity(&fset);

		if(do_purge) {
			purge();
			do_purge = false;
		}

		/* Let's check if everybody is still alive */

		if(last_ping_check + pingtimeout < now) {
			check_dead_connections();
			last_ping_check = now;

			if(routing_mode == RMODE_SWITCH)
				age_mac();

			age_past_requests();

			/* Should we regenerate our key? */

			if(keyexpires < now) {
				ifdebug(STATUS) logger(LOG_INFO, _("Regenerating symmetric key"));

				RAND_pseudo_bytes(myself->key, myself->keylength);
				if(myself->cipher)
					EVP_DecryptInit_ex(&packet_ctx, myself->cipher, NULL, myself->key, myself->key + myself->cipher->key_len);
				send_key_changed(broadcast, myself);
				keyexpires = now + keylifetime;
			}
		}


		while((event = get_expired_event())) {
			event->handler(event->data);
			free(event);
		}

		if(sigalrm) {
			logger(LOG_INFO, _("Flushing event queue"));

			while(event_tree->head) {
				event = (event_t *) event_tree->head->data;
				event->handler(event->data);
				event_del(event);
			}
			sigalrm = false;
		}

		if(sighup) {
			connection_t *c;
			avl_node_t *node;
			char *fname;
			struct stat s;
			
			sighup = false;
			
			/* Reread our own configuration file */

			exit_configuration(&config_tree);
			init_configuration(&config_tree);

			if(!read_server_config()) {
				logger(LOG_ERR, _("Unable to reread configuration file, exitting."));
				exit(1);
			}

			/* Close connections to hosts that have a changed or deleted host config file */
			
			for(node = connection_tree->head; node; node = node->next) {
				c = (connection_t *) node->data;
				
				if(c->outgoing) {
					free(c->outgoing->name);
					freeaddrinfo(c->outgoing->ai);
					free(c->outgoing);
					c->outgoing = NULL;
				}
				
				asprintf(&fname, "%s/hosts/%s", confbase, c->name);
				if(stat(fname, &s) || s.st_mtime > last_config_check)
					terminate_connection(c, c->status.active);
				free(fname);
			}

			last_config_check = now;

			/* Try to make outgoing connections */
			
			try_outgoing_connections();
						
			continue;
		}
	}
}
