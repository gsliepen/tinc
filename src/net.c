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
#include "xalloc.h"

bool do_purge = false;
volatile bool running = false;
#ifdef HAVE_PSELECT
bool graph_dump = false;
#endif

time_t now = 0;
int contradicting_add_edge = 0;
int contradicting_del_edge = 0;
static int sleeptime = 10;

/* Purge edges and subnets of unreachable nodes. Use carefully. */

static void purge(void) {
	avl_node_t *nnode, *nnext, *enode, *enext, *snode, *snext;
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
  put all file descriptors in an fd_set array
  While we're at it, purge stuff that needs to be removed.
*/
static int build_fdset(fd_set *readset, fd_set *writeset) {
	avl_node_t *node, *next;
	connection_t *c;
	int i, max = 0;

	FD_ZERO(readset);
	FD_ZERO(writeset);

	for(node = connection_tree->head; node; node = next) {
		next = node->next;
		c = node->data;

		if(c->status.remove) {
			connection_del(c);
			if(!connection_tree->head)
				purge();
		} else {
			FD_SET(c->socket, readset);
			if(c->outbuflen > 0)
				FD_SET(c->socket, writeset);
			if(c->socket > max)
				max = c->socket;
		}
	}

	for(i = 0; i < listen_sockets; i++) {
		FD_SET(listen_socket[i].tcp, readset);
		if(listen_socket[i].tcp > max)
			max = listen_socket[i].tcp;
		FD_SET(listen_socket[i].udp, readset);
		if(listen_socket[i].udp > max)
			max = listen_socket[i].udp;
	}

	if(device_fd >= 0)
		FD_SET(device_fd, readset);
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
void terminate_connection(connection_t *c, bool report) {
	if(c->status.remove)
		return;

	ifdebug(CONNECTIONS) logger(LOG_NOTICE, "Closing connection with %s (%s)",
			   c->name, c->hostname);

	c->status.remove = true;
	c->status.active = false;

	if(c->node)
		c->node->connection = NULL;

	if(c->socket)
		closesocket(c->socket);

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
static void check_dead_connections(void) {
	avl_node_t *node, *next;
	connection_t *c;

	for(node = connection_tree->head; node; node = next) {
		next = node->next;
		c = node->data;

		if(c->last_ping_time + pingtimeout <= now) {
			if(c->status.active) {
				if(c->status.pinged) {
					ifdebug(CONNECTIONS) logger(LOG_INFO, "%s (%s) didn't respond to PING in %ld seconds",
							   c->name, c->hostname, now - c->last_ping_time);
					c->status.timeout = true;
					terminate_connection(c, true);
				} else if(c->last_ping_time + pinginterval <= now) {
					send_ping(c);
				}
			} else {
				if(c->status.remove) {
					logger(LOG_WARNING, "Old connection_t for %s (%s) status %04x still lingering, deleting...",
						   c->name, c->hostname, bitfield_to_int(&c->status, sizeof c->status));
					connection_del(c);
					continue;
				}
				ifdebug(CONNECTIONS) logger(LOG_WARNING, "Timeout from %s (%s) during authentication",
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

		if(c->outbuflen > 0 && c->last_flushed_time + pingtimeout <= now) {
			if(c->status.active) {
				ifdebug(CONNECTIONS) logger(LOG_INFO,
						"%s (%s) could not flush for %ld seconds (%d bytes remaining)",
						c->name, c->hostname, now - c->last_flushed_time, c->outbuflen);
				c->status.timeout = true;
				terminate_connection(c, true);
			}
		}
	}
}

/*
  check all connections to see if anything
  happened on their sockets
*/
static void check_network_activity(fd_set * readset, fd_set * writeset) {
	connection_t *c;
	avl_node_t *node;
	int result, i;
	socklen_t len = sizeof(result);
	vpn_packet_t packet;
	static int errors = 0;

	/* check input from kernel */
	if(device_fd >= 0 && FD_ISSET(device_fd, readset)) {
		if(read_packet(&packet)) {
			errors = 0;
			packet.priority = 0;
			route(myself, &packet);
		} else {
			usleep(errors * 50000);
			errors++;
			if(errors > 10) {
				logger(LOG_ERR, "Too many errors from %s, exiting!", device);
				running = false;
			}
		}
	}

	/* check meta connections */
	for(node = connection_tree->head; node; node = node->next) {
		c = node->data;

		if(c->status.remove)
			continue;

		if(FD_ISSET(c->socket, readset)) {
			if(c->status.connecting) {
				c->status.connecting = false;
				getsockopt(c->socket, SOL_SOCKET, SO_ERROR, (void *)&result, &len);

				if(!result)
					finish_connecting(c);
				else {
					ifdebug(CONNECTIONS) logger(LOG_DEBUG,
							   "Error while connecting to %s (%s): %s",
							   c->name, c->hostname, sockstrerror(result));
					closesocket(c->socket);
					do_outgoing_connection(c);
					continue;
				}
			}

			if(!receive_meta(c)) {
				terminate_connection(c, c->status.active);
				continue;
			}
		}

		if(FD_ISSET(c->socket, writeset)) {
			if(!flush_meta(c)) {
				terminate_connection(c, c->status.active);
				continue;
			}
		}
	}

	for(i = 0; i < listen_sockets; i++) {
		if(FD_ISSET(listen_socket[i].udp, readset))
			handle_incoming_vpn_data(listen_socket[i].udp);

		if(FD_ISSET(listen_socket[i].tcp, readset))
			handle_new_meta_connection(listen_socket[i].tcp);
	}
}

/*
  this is where it all happens...
*/
int main_loop(void) {
	fd_set readset, writeset;
#ifdef HAVE_PSELECT
	struct timespec tv;
	sigset_t omask, block_mask;
	time_t next_event;
#else
	struct timeval tv;
#endif
	int r, maxfd;
	time_t last_ping_check, last_config_check, last_graph_dump;
	event_t *event;

	last_ping_check = now;
	last_config_check = now;
	last_graph_dump = now;
	
	srand(now);

#ifdef HAVE_PSELECT
	if(lookup_config(config_tree, "GraphDumpFile"))
		graph_dump = true;
	/* Block SIGHUP & SIGALRM */
	sigemptyset(&block_mask);
	sigaddset(&block_mask, SIGHUP);
	sigaddset(&block_mask, SIGALRM);
	sigprocmask(SIG_BLOCK, &block_mask, &omask);
#endif

	running = true;

	while(running) {
#ifdef HAVE_PSELECT
		next_event = last_ping_check + pingtimeout;
		if(graph_dump && next_event > last_graph_dump + 60)
			next_event = last_graph_dump + 60;

		if((event = peek_next_event()) && next_event > event->time)
			next_event = event->time;

		if(next_event <= now)
			tv.tv_sec = 0;
		else
			tv.tv_sec = next_event - now;
		tv.tv_nsec = 0;
#else
		tv.tv_sec = 1;
		tv.tv_usec = 0;
#endif

		maxfd = build_fdset(&readset, &writeset);

#ifdef HAVE_MINGW
		LeaveCriticalSection(&mutex);
#endif
#ifdef HAVE_PSELECT
		r = pselect(maxfd + 1, &readset, &writeset, NULL, &tv, &omask);
#else
		r = select(maxfd + 1, &readset, &writeset, NULL, &tv);
#endif
		now = time(NULL);
#ifdef HAVE_MINGW
		EnterCriticalSection(&mutex);
#endif

		if(r < 0) {
			if(!sockwouldblock(sockerrno)) {
				logger(LOG_ERR, "Error while waiting for input: %s", sockstrerror(sockerrno));
				dump_connections();
				return 1;
			}
		}

		if(r > 0)
			check_network_activity(&readset, &writeset);

		if(do_purge) {
			purge();
			do_purge = false;
		}

		/* Let's check if everybody is still alive */

		if(last_ping_check + pingtimeout <= now) {
			check_dead_connections();
			last_ping_check = now;

			if(routing_mode == RMODE_SWITCH)
				age_subnets();

			age_past_requests();

			/* Should we regenerate our key? */

			if(keyexpires <= now) {
				avl_node_t *node;
				node_t *n;

				ifdebug(STATUS) logger(LOG_INFO, "Expiring symmetric keys");

				for(node = node_tree->head; node; node = node->next) {
					n = node->data;
					if(n->inkey) {
						free(n->inkey);
						n->inkey = NULL;
					}
				}

				send_key_changed();
				keyexpires = now + keylifetime;
			}

			/* Detect ADD_EDGE/DEL_EDGE storms that are caused when
			 * two tinc daemons with the same name are on the VPN.
			 * If so, sleep a while. If this happens multiple times
			 * in a row, sleep longer. */

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
		}

		if(sigalrm) {
			avl_node_t *node;
			logger(LOG_INFO, "Flushing event queue");
			expire_events();
			for(node = connection_tree->head; node; node = node->next) {
				connection_t *c = node->data;
				send_ping(c);
			}
			sigalrm = false;
		}

		while((event = get_expired_event())) {
			event->handler(event->data);
			free_event(event);
		}

		if(sighup) {
			connection_t *c;
			avl_node_t *node, *next;
			char *fname;
			struct stat s;
			
			sighup = false;

			reopenlogger();
			
			/* Reread our own configuration file */

			exit_configuration(&config_tree);
			init_configuration(&config_tree);

			if(!read_server_config()) {
				logger(LOG_ERR, "Unable to reread configuration file, exitting.");
				return 1;
			}

			/* Cancel non-active outgoing connections */

			for(node = connection_tree->head; node; node = next) {
				next = node->next;
				c = node->data;

				c->outgoing = NULL;

				if(c->status.connecting) {
					terminate_connection(c, false);
					connection_del(c);
				}
			}

			/* Wipe list of outgoing connections */

			for(list_node_t *node = outgoing_list->head; node; node = node->next) {
				outgoing_t *outgoing = node->data;

				if(outgoing->event)
					event_del(outgoing->event);
			}

			list_delete_list(outgoing_list);

			/* Close connections to hosts that have a changed or deleted host config file */
			
			for(node = connection_tree->head; node; node = node->next) {
				c = node->data;
				
				xasprintf(&fname, "%s/hosts/%s", confbase, c->name);
				if(stat(fname, &s) || s.st_mtime > last_config_check)
					terminate_connection(c, c->status.active);
				free(fname);
			}

			last_config_check = now;

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
		}
		
		/* Dump graph if wanted every 60 seconds*/

		if(last_graph_dump + 60 <= now) {
			dump_graph();
			last_graph_dump = now;
		}
	}

#ifdef HAVE_PSELECT
	/* Restore SIGHUP & SIGALARM mask */
	sigprocmask(SIG_SETMASK, &omask, NULL);
#endif

	return 0;
}
