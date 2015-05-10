/*
    net_socket.c -- Handle various kinds of sockets.
    Copyright (C) 1998-2005 Ivo Timmermans,
                  2000-2014 Guus Sliepen <guus@tinc-vpn.org>
                  2006      Scott Lamb <slamb@slamb.org>
                  2009      Florian Forster <octo@verplant.org>

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
#include "control_common.h"
#include "list.h"
#include "logger.h"
#include "meta.h"
#include "names.h"
#include "net.h"
#include "netutl.h"
#include "protocol.h"
#include "utils.h"
#include "xalloc.h"

/* Needed on Mac OS/X */
#ifndef SOL_TCP
#define SOL_TCP IPPROTO_TCP
#endif

int addressfamily = AF_UNSPEC;
int maxtimeout = 900;
int seconds_till_retry = 5;
int udp_rcvbuf = 1024 * 1024;
int udp_sndbuf = 1024 * 1024;
int max_connection_burst = 100;

listen_socket_t listen_socket[MAXSOCKETS];
int listen_sockets;
#ifndef HAVE_MINGW
io_t unix_socket;
#endif
list_t *outgoing_list = NULL;

/* Setup sockets */

static void configure_tcp(connection_t *c) {
	int option;

#ifdef O_NONBLOCK
	int flags = fcntl(c->socket, F_GETFL);

	if(fcntl(c->socket, F_SETFL, flags | O_NONBLOCK) < 0) {
		logger(DEBUG_ALWAYS, LOG_ERR, "fcntl for %s: %s", c->hostname, strerror(errno));
	}
#elif defined(WIN32)
	unsigned long arg = 1;

	if(ioctlsocket(c->socket, FIONBIO, &arg) != 0) {
		logger(DEBUG_ALWAYS, LOG_ERR, "ioctlsocket for %s: %s", c->hostname, sockstrerror(sockerrno));
	}
#endif

#if defined(SOL_TCP) && defined(TCP_NODELAY)
	option = 1;
	setsockopt(c->socket, SOL_TCP, TCP_NODELAY, (void *)&option, sizeof option);
#endif

#if defined(SOL_IP) && defined(IP_TOS) && defined(IPTOS_LOWDELAY)
	option = IPTOS_LOWDELAY;
	setsockopt(c->socket, SOL_IP, IP_TOS, (void *)&option, sizeof option);
#endif
}

static bool bind_to_interface(int sd) {
	char *iface;

#if defined(SOL_SOCKET) && defined(SO_BINDTODEVICE)
	struct ifreq ifr;
	int status;
#endif /* defined(SOL_SOCKET) && defined(SO_BINDTODEVICE) */

	if(!get_config_string (lookup_config (config_tree, "BindToInterface"), &iface))
		return true;

#if defined(SOL_SOCKET) && defined(SO_BINDTODEVICE)
	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_ifrn.ifrn_name, iface, IFNAMSIZ);
	ifr.ifr_ifrn.ifrn_name[IFNAMSIZ - 1] = 0;

	status = setsockopt(sd, SOL_SOCKET, SO_BINDTODEVICE, (void *)&ifr, sizeof(ifr));
	if(status) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Can't bind to interface %s: %s", iface,
				sockstrerror(sockerrno));
		return false;
	}
#else /* if !defined(SOL_SOCKET) || !defined(SO_BINDTODEVICE) */
	logger(DEBUG_ALWAYS, LOG_WARNING, "%s not supported on this platform", "BindToInterface");
#endif

	return true;
}

static bool bind_to_address(connection_t *c) {
	int s = -1;

	for(int i = 0; i < listen_sockets && listen_socket[i].bindto; i++) {
		if(listen_socket[i].sa.sa.sa_family != c->address.sa.sa_family)
			continue;
		if(s >= 0)
			return false;
		s = i;
	}

	if(s < 0)
		return false;

	sockaddr_t sa = listen_socket[s].sa;
	if(sa.sa.sa_family == AF_INET)
		sa.in.sin_port = 0;
	else if(sa.sa.sa_family == AF_INET6)
		sa.in6.sin6_port = 0;

	if(bind(c->socket, &sa.sa, SALEN(sa.sa))) {
		logger(DEBUG_CONNECTIONS, LOG_WARNING, "Can't bind outgoing socket: %s", sockstrerror(sockerrno));
		return false;
	}

	return true;
}

int setup_listen_socket(const sockaddr_t *sa) {
	int nfd;
	char *addrstr;
	int option;
	char *iface;

	nfd = socket(sa->sa.sa_family, SOCK_STREAM, IPPROTO_TCP);

	if(nfd < 0) {
		logger(DEBUG_STATUS, LOG_ERR, "Creating metasocket failed: %s", sockstrerror(sockerrno));
		return -1;
	}

#ifdef FD_CLOEXEC
	fcntl(nfd, F_SETFD, FD_CLOEXEC);
#endif

	/* Optimize TCP settings */

	option = 1;
	setsockopt(nfd, SOL_SOCKET, SO_REUSEADDR, (void *)&option, sizeof option);

#if defined(SOL_IPV6) && defined(IPV6_V6ONLY)
	if(sa->sa.sa_family == AF_INET6)
		setsockopt(nfd, SOL_IPV6, IPV6_V6ONLY, (void *)&option, sizeof option);
#endif

	if(get_config_string
	   (lookup_config(config_tree, "BindToInterface"), &iface)) {
#if defined(SOL_SOCKET) && defined(SO_BINDTODEVICE)
		struct ifreq ifr;

		memset(&ifr, 0, sizeof ifr);
		strncpy(ifr.ifr_ifrn.ifrn_name, iface, IFNAMSIZ);

		if(setsockopt(nfd, SOL_SOCKET, SO_BINDTODEVICE, (void *)&ifr, sizeof ifr)) {
			closesocket(nfd);
			logger(DEBUG_ALWAYS, LOG_ERR, "Can't bind to interface %s: %s", iface,
				   sockstrerror(sockerrno));
			return -1;
		}
#else
		logger(DEBUG_ALWAYS, LOG_WARNING, "%s not supported on this platform", "BindToInterface");
#endif
	}

	if(bind(nfd, &sa->sa, SALEN(sa->sa))) {
		closesocket(nfd);
		addrstr = sockaddr2hostname(sa);
		logger(DEBUG_ALWAYS, LOG_ERR, "Can't bind to %s/tcp: %s", addrstr, sockstrerror(sockerrno));
		free(addrstr);
		return -1;
	}

	if(listen(nfd, 3)) {
		closesocket(nfd);
		logger(DEBUG_ALWAYS, LOG_ERR, "System call `%s' failed: %s", "listen", sockstrerror(sockerrno));
		return -1;
	}

	return nfd;
}

int setup_vpn_in_socket(const sockaddr_t *sa) {
	int nfd;
	char *addrstr;
	int option;

	nfd = socket(sa->sa.sa_family, SOCK_DGRAM, IPPROTO_UDP);

	if(nfd < 0) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Creating UDP socket failed: %s", sockstrerror(sockerrno));
		return -1;
	}

#ifdef FD_CLOEXEC
	fcntl(nfd, F_SETFD, FD_CLOEXEC);
#endif

#ifdef O_NONBLOCK
	{
		int flags = fcntl(nfd, F_GETFL);

		if(fcntl(nfd, F_SETFL, flags | O_NONBLOCK) < 0) {
			closesocket(nfd);
			logger(DEBUG_ALWAYS, LOG_ERR, "System call `%s' failed: %s", "fcntl",
				   strerror(errno));
			return -1;
		}
	}
#elif defined(WIN32)
	{
		unsigned long arg = 1;
		if(ioctlsocket(nfd, FIONBIO, &arg) != 0) {
			closesocket(nfd);
			logger(DEBUG_ALWAYS, LOG_ERR, "Call to `%s' failed: %s", "ioctlsocket", sockstrerror(sockerrno));
			return -1;
		}
	}
#endif

	option = 1;
	setsockopt(nfd, SOL_SOCKET, SO_REUSEADDR, (void *)&option, sizeof option);
	setsockopt(nfd, SOL_SOCKET, SO_BROADCAST, (void *)&option, sizeof option);

	if(udp_rcvbuf && setsockopt(nfd, SOL_SOCKET, SO_RCVBUF, (void *)&udp_rcvbuf, sizeof(udp_rcvbuf)))
		logger(DEBUG_ALWAYS, LOG_WARNING, "Can't set UDP SO_RCVBUF to %i: %s", udp_rcvbuf, sockstrerror(sockerrno));

	if(udp_sndbuf && setsockopt(nfd, SOL_SOCKET, SO_SNDBUF, (void *)&udp_sndbuf, sizeof(udp_sndbuf)))
		logger(DEBUG_ALWAYS, LOG_WARNING, "Can't set UDP SO_SNDBUF to %i: %s", udp_sndbuf, sockstrerror(sockerrno));

#if defined(IPPROTO_IPV6) && defined(IPV6_V6ONLY)
	if(sa->sa.sa_family == AF_INET6)
		setsockopt(nfd, IPPROTO_IPV6, IPV6_V6ONLY, (void *)&option, sizeof option);
#endif

#if defined(IP_DONTFRAG) && !defined(IP_DONTFRAGMENT)
#define IP_DONTFRAGMENT IP_DONTFRAG
#endif

#if defined(SOL_IP) && defined(IP_MTU_DISCOVER) && defined(IP_PMTUDISC_DO)
	if(myself->options & OPTION_PMTU_DISCOVERY) {
		option = IP_PMTUDISC_DO;
		setsockopt(nfd, SOL_IP, IP_MTU_DISCOVER, (void *)&option, sizeof(option));
	}
#elif defined(IPPROTO_IP) && defined(IP_DONTFRAGMENT)
	if(myself->options & OPTION_PMTU_DISCOVERY) {
		option = 1;
		setsockopt(nfd, IPPROTO_IP, IP_DONTFRAGMENT, (void *)&option, sizeof(option));
	}
#endif

#if defined(SOL_IPV6) && defined(IPV6_MTU_DISCOVER) && defined(IPV6_PMTUDISC_DO)
	if(myself->options & OPTION_PMTU_DISCOVERY) {
		option = IPV6_PMTUDISC_DO;
		setsockopt(nfd, SOL_IPV6, IPV6_MTU_DISCOVER, (void *)&option, sizeof(option));
	}
#elif defined(IPPROTO_IPV6) && defined(IPV6_DONTFRAG)
	if(myself->options & OPTION_PMTU_DISCOVERY) {
		option = 1;
		setsockopt(nfd, IPPROTO_IPV6, IPV6_DONTFRAG, (void *)&option, sizeof(option));
	}
#endif

	if (!bind_to_interface(nfd)) {
		closesocket(nfd);
		return -1;
	}

	if(bind(nfd, &sa->sa, SALEN(sa->sa))) {
		closesocket(nfd);
		addrstr = sockaddr2hostname(sa);
		logger(DEBUG_ALWAYS, LOG_ERR, "Can't bind to %s/udp: %s", addrstr, sockstrerror(sockerrno));
		free(addrstr);
		return -1;
	}

	return nfd;
} /* int setup_vpn_in_socket */

static void retry_outgoing_handler(void *data) {
	setup_outgoing_connection(data);
}

void retry_outgoing(outgoing_t *outgoing) {
	outgoing->timeout += 5;

	if(outgoing->timeout > maxtimeout)
		outgoing->timeout = maxtimeout;

	timeout_add(&outgoing->ev, retry_outgoing_handler, outgoing, &(struct timeval){outgoing->timeout, rand() % 100000});

	logger(DEBUG_CONNECTIONS, LOG_NOTICE, "Trying to re-establish outgoing connection in %d seconds", outgoing->timeout);
}

void finish_connecting(connection_t *c) {
	logger(DEBUG_CONNECTIONS, LOG_INFO, "Connected to %s (%s)", c->name, c->hostname);

	c->last_ping_time = now;
	c->status.connecting = false;

	send_id(c);
}

static void do_outgoing_pipe(connection_t *c, char *command) {
#ifndef HAVE_MINGW
	int fd[2];

	if(socketpair(AF_UNIX, SOCK_STREAM, 0, fd)) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Could not create socketpair: %s", sockstrerror(sockerrno));
		return;
	}

	if(fork()) {
		c->socket = fd[0];
		close(fd[1]);
		logger(DEBUG_CONNECTIONS, LOG_DEBUG, "Using proxy %s", command);
		return;
	}

	close(0);
	close(1);
	close(fd[0]);
	dup2(fd[1], 0);
	dup2(fd[1], 1);
	close(fd[1]);

	// Other filedescriptors should be closed automatically by CLOEXEC

	char *host = NULL;
	char *port = NULL;

	sockaddr2str(&c->address, &host, &port);
	setenv("REMOTEADDRESS", host, true);
	setenv("REMOTEPORT", port, true);
	setenv("NODE", c->name, true);
	setenv("NAME", myself->name, true);
	if(netname)
		setenv("NETNAME", netname, true);

	int result = system(command);
	if(result < 0)
		logger(DEBUG_ALWAYS, LOG_ERR, "Could not execute %s: %s", command, strerror(errno));
	else if(result)
		logger(DEBUG_ALWAYS, LOG_ERR, "%s exited with non-zero status %d", command, result);
	exit(result);
#else
	logger(DEBUG_ALWAYS, LOG_ERR, "Proxy type exec not supported on this platform!");
	return;
#endif
}

static void handle_meta_write(connection_t *c) {
	if(c->outbuf.len <= c->outbuf.offset)
		return;

	ssize_t outlen = send(c->socket, c->outbuf.data + c->outbuf.offset, c->outbuf.len - c->outbuf.offset, 0);
	if(outlen <= 0) {
		if(!sockerrno || sockerrno == EPIPE) {
			logger(DEBUG_CONNECTIONS, LOG_NOTICE, "Connection closed by %s (%s)", c->name, c->hostname);
		} else if(sockwouldblock(sockerrno)) {
			logger(DEBUG_CONNECTIONS, LOG_DEBUG, "Sending %d bytes to %s (%s) would block", c->outbuf.len - c->outbuf.offset, c->name, c->hostname);
			return;
		} else {
			logger(DEBUG_CONNECTIONS, LOG_ERR, "Could not send %d bytes of data to %s (%s): %s", c->outbuf.len - c->outbuf.offset, c->name, c->hostname, sockstrerror(sockerrno));
		}

		terminate_connection(c, c->edge);
		return;
	}

	buffer_read(&c->outbuf, outlen);
	if(!c->outbuf.len)
		io_set(&c->io, IO_READ);
}

static void handle_meta_io(void *data, int flags) {
	connection_t *c = data;

	if(c->status.connecting) {
		/*
		   The event loop does not protect against spurious events. Verify that we are actually connected
		   by issuing an empty send() call.

		   Note that the behavior of send() on potentially unconnected sockets differ between platforms:
		   +------------+-----------+-------------+-----------+
		   |   Event    |   POSIX   |    Linux    |  Windows  |
		   +------------+-----------+-------------+-----------+
		   | Spurious   | ENOTCONN  | EWOULDBLOCK | ENOTCONN  |
		   | Failed     | ENOTCONN  | (cause)     | ENOTCONN  |
		   | Successful | (success) | (success)   | (success) |
		   +------------+-----------+-------------+-----------+
		*/
		if (send(c->socket, NULL, 0, 0) != 0) {
			if (sockwouldblock(sockerrno))
				return;
			int socket_error;
			if (!socknotconn(sockerrno))
				socket_error = sockerrno;
			else {
				socklen_t len = sizeof socket_error;
				getsockopt(c->socket, SOL_SOCKET, SO_ERROR, (void *)&socket_error, &len);
			}
			if (socket_error) {
				logger(DEBUG_CONNECTIONS, LOG_DEBUG, "Error while connecting to %s (%s): %s", c->name, c->hostname, sockstrerror(socket_error));
				terminate_connection(c, false);
			}
			return;
		}

		c->status.connecting = false;
		finish_connecting(c);
	}

	if(flags & IO_WRITE)
		handle_meta_write(c);
	else
		handle_meta_connection_data(c);
}

bool do_outgoing_connection(outgoing_t *outgoing) {
	char *address, *port, *space;
	struct addrinfo *proxyai = NULL;
	int result;

begin:
	if(!outgoing->ai) {
		if(!outgoing->cfg) {
			logger(DEBUG_CONNECTIONS, LOG_ERR, "Could not set up a meta connection to %s", outgoing->name);
			retry_outgoing(outgoing);
			return false;
		}

		get_config_string(outgoing->cfg, &address);

		space = strchr(address, ' ');
		if(space) {
			port = xstrdup(space + 1);
			*space = 0;
		} else {
			if(!get_config_string(lookup_config(outgoing->config_tree, "Port"), &port))
				port = xstrdup("655");
		}

		outgoing->ai = str2addrinfo(address, port, SOCK_STREAM);
		free(address);
		free(port);

		outgoing->aip = outgoing->ai;
		outgoing->cfg = lookup_config_next(outgoing->config_tree, outgoing->cfg);
	}

	if(!outgoing->aip) {
		if(outgoing->ai)
			freeaddrinfo(outgoing->ai);
		outgoing->ai = NULL;
		goto begin;
	}

	connection_t *c = new_connection();
	c->outgoing = outgoing;

	memcpy(&c->address, outgoing->aip->ai_addr, outgoing->aip->ai_addrlen);
	outgoing->aip = outgoing->aip->ai_next;

	c->hostname = sockaddr2hostname(&c->address);

	logger(DEBUG_CONNECTIONS, LOG_INFO, "Trying to connect to %s (%s)", outgoing->name, c->hostname);

	if(!proxytype) {
		c->socket = socket(c->address.sa.sa_family, SOCK_STREAM, IPPROTO_TCP);
		configure_tcp(c);
	} else if(proxytype == PROXY_EXEC) {
		do_outgoing_pipe(c, proxyhost);
	} else {
		proxyai = str2addrinfo(proxyhost, proxyport, SOCK_STREAM);
		if(!proxyai) {
			free_connection(c);
			goto begin;
		}
		logger(DEBUG_CONNECTIONS, LOG_INFO, "Using proxy at %s port %s", proxyhost, proxyport);
		c->socket = socket(proxyai->ai_family, SOCK_STREAM, IPPROTO_TCP);
		configure_tcp(c);
	}

	if(c->socket == -1) {
		logger(DEBUG_CONNECTIONS, LOG_ERR, "Creating socket for %s failed: %s", c->hostname, sockstrerror(sockerrno));
		free_connection(c);
		goto begin;
	}

#ifdef FD_CLOEXEC
	fcntl(c->socket, F_SETFD, FD_CLOEXEC);
#endif

	if(proxytype != PROXY_EXEC) {
#if defined(SOL_IPV6) && defined(IPV6_V6ONLY)
		int option = 1;
		if(c->address.sa.sa_family == AF_INET6)
			setsockopt(c->socket, SOL_IPV6, IPV6_V6ONLY, (void *)&option, sizeof option);
#endif

		bind_to_interface(c->socket);
		bind_to_address(c);
	}

	/* Connect */

	if(!proxytype) {
		result = connect(c->socket, &c->address.sa, SALEN(c->address.sa));
	} else if(proxytype == PROXY_EXEC) {
		result = 0;
	} else {
		result = connect(c->socket, proxyai->ai_addr, proxyai->ai_addrlen);
		freeaddrinfo(proxyai);
	}

	if(result == -1 && !sockinprogress(sockerrno)) {
		logger(DEBUG_CONNECTIONS, LOG_ERR, "Could not connect to %s (%s): %s", outgoing->name, c->hostname, sockstrerror(sockerrno));
		free_connection(c);

		goto begin;
	}

	/* Now that there is a working socket, fill in the rest and register this connection. */

	c->status.connecting = true;
	c->name = xstrdup(outgoing->name);
#ifndef DISABLE_LEGACY
	c->outcipher = myself->connection->outcipher;
	c->outdigest = myself->connection->outdigest;
#endif
	c->outmaclength = myself->connection->outmaclength;
	c->outcompression = myself->connection->outcompression;
	c->last_ping_time = now;

	connection_add(c);

	io_add(&c->io, handle_meta_io, c, c->socket, IO_READ|IO_WRITE);

	return true;
}

// Find edges pointing to this node, and use them to build a list of unique, known addresses.
static struct addrinfo *get_known_addresses(node_t *n) {
	struct addrinfo *ai = NULL;

	for splay_each(edge_t, e, n->edge_tree) {
		if(!e->reverse)
			continue;

		bool found = false;
		for(struct addrinfo *aip = ai; aip; aip = aip->ai_next) {
			if(!sockaddrcmp(&e->reverse->address, (sockaddr_t *)aip->ai_addr)) {
				found = true;
				break;
			}
		}
		if(found)
			continue;

		struct addrinfo *nai = xzalloc(sizeof *nai);
		if(ai)
			ai->ai_next = nai;
		ai = nai;
		ai->ai_family = e->reverse->address.sa.sa_family;
		ai->ai_socktype = SOCK_STREAM;
		ai->ai_protocol = IPPROTO_TCP;
		ai->ai_addrlen = SALEN(e->reverse->address.sa);
		ai->ai_addr = xmalloc(ai->ai_addrlen);
		memcpy(ai->ai_addr, &e->reverse->address, ai->ai_addrlen);
	}

	return ai;
}

void setup_outgoing_connection(outgoing_t *outgoing) {
	timeout_del(&outgoing->ev);

	node_t *n = lookup_node(outgoing->name);

	if(n && n->connection) {
		logger(DEBUG_CONNECTIONS, LOG_INFO, "Already connected to %s", outgoing->name);

		n->connection->outgoing = outgoing;
		return;
	}

	init_configuration(&outgoing->config_tree);
	read_host_config(outgoing->config_tree, outgoing->name);
	outgoing->cfg = lookup_config(outgoing->config_tree, "Address");

	if(!outgoing->cfg) {
		if(n)
			outgoing->aip = outgoing->ai = get_known_addresses(n);
		if(!outgoing->ai) {
			logger(DEBUG_ALWAYS, LOG_ERR, "No address known for %s", outgoing->name);
			return;
		}
	}

	do_outgoing_connection(outgoing);
}

/*
  accept a new tcp connect and create a
  new connection
*/
void handle_new_meta_connection(void *data, int flags) {
	listen_socket_t *l = data;
	connection_t *c;
	sockaddr_t sa;
	int fd;
	socklen_t len = sizeof sa;

	fd = accept(l->tcp.fd, &sa.sa, &len);

	if(fd < 0) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Accepting a new connection failed: %s", sockstrerror(sockerrno));
		return;
	}

	sockaddrunmap(&sa);

	// Check if we get many connections from the same host

	static sockaddr_t prev_sa;
	static int tarpit = -1;

	if(tarpit >= 0) {
		closesocket(tarpit);
		tarpit = -1;
	}

	if(!sockaddrcmp_noport(&sa, &prev_sa)) {
		static int samehost_burst;
		static int samehost_burst_time;

		if(now.tv_sec - samehost_burst_time > samehost_burst)
			samehost_burst = 0;
		else
			samehost_burst -= now.tv_sec - samehost_burst_time;

		samehost_burst_time = now.tv_sec;
		samehost_burst++;

		if(samehost_burst > max_connection_burst) {
			tarpit = fd;
			return;
		}
	}

	memcpy(&prev_sa, &sa, sizeof sa);

	// Check if we get many connections from different hosts

	static int connection_burst;
	static int connection_burst_time;

	if(now.tv_sec - connection_burst_time > connection_burst)
		connection_burst = 0;
	else
		connection_burst -= now.tv_sec - connection_burst_time;

	connection_burst_time = now.tv_sec;
	connection_burst++;

	if(connection_burst >= max_connection_burst) {
		connection_burst = max_connection_burst;
		tarpit = fd;
		return;
	}

	// Accept the new connection

	c = new_connection();
	c->name = xstrdup("<unknown>");
#ifndef DISABLE_LEGACY
	c->outcipher = myself->connection->outcipher;
	c->outdigest = myself->connection->outdigest;
#endif
	c->outmaclength = myself->connection->outmaclength;
	c->outcompression = myself->connection->outcompression;

	c->address = sa;
	c->hostname = sockaddr2hostname(&sa);
	c->socket = fd;
	c->last_ping_time = now;

	logger(DEBUG_CONNECTIONS, LOG_NOTICE, "Connection from %s", c->hostname);

	io_add(&c->io, handle_meta_io, c, c->socket, IO_READ);

	configure_tcp(c);

	connection_add(c);

	c->allow_request = ID;
	send_id(c);
}

#ifndef HAVE_MINGW
/*
  accept a new UNIX socket connection
*/
void handle_new_unix_connection(void *data, int flags) {
	io_t *io = data;
	connection_t *c;
	sockaddr_t sa;
	int fd;
	socklen_t len = sizeof sa;

	fd = accept(io->fd, &sa.sa, &len);

	if(fd < 0) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Accepting a new connection failed: %s", sockstrerror(sockerrno));
		return;
	}

	sockaddrunmap(&sa);

	c = new_connection();
	c->name = xstrdup("<control>");
	c->address = sa;
	c->hostname = xstrdup("localhost port unix");
	c->socket = fd;
	c->last_ping_time = now;

	logger(DEBUG_CONNECTIONS, LOG_NOTICE, "Connection from %s", c->hostname);

	io_add(&c->io, handle_meta_io, c, c->socket, IO_READ);

	connection_add(c);

	c->allow_request = ID;

	send_id(c);
}
#endif

static void free_outgoing(outgoing_t *outgoing) {
	timeout_del(&outgoing->ev);

	if(outgoing->ai)
		freeaddrinfo(outgoing->ai);

	if(outgoing->config_tree)
		exit_configuration(&outgoing->config_tree);

	if(outgoing->name)
		free(outgoing->name);

	free(outgoing);
}

void try_outgoing_connections(void) {
	/* If there is no outgoing list yet, create one. Otherwise, mark all outgoings as deleted. */

	if(!outgoing_list) {
		outgoing_list = list_alloc((list_action_t)free_outgoing);
	} else {
		for list_each(outgoing_t, outgoing, outgoing_list)
			outgoing->timeout = -1;
	}

	/* Make sure there is one outgoing_t in the list for each ConnectTo. */

	for(config_t *cfg = lookup_config(config_tree, "ConnectTo"); cfg; cfg = lookup_config_next(config_tree, cfg)) {
		char *name;
		get_config_string(cfg, &name);

		if(!check_id(name)) {
			logger(DEBUG_ALWAYS, LOG_ERR,
				   "Invalid name for outgoing connection in %s line %d",
				   cfg->file, cfg->line);
			free(name);
			continue;
		}

		bool found = false;

		for list_each(outgoing_t, outgoing, outgoing_list) {
			if(!strcmp(outgoing->name, name)) {
				found = true;
				outgoing->timeout = 0;
				break;
			}
		}

		if(!found) {
			outgoing_t *outgoing = xzalloc(sizeof *outgoing);
			outgoing->name = name;
			list_insert_tail(outgoing_list, outgoing);
			setup_outgoing_connection(outgoing);
		}
	}

	/* Terminate any connections whose outgoing_t is to be deleted. */

	for list_each(connection_t, c, connection_list) {
		if(c->outgoing && c->outgoing->timeout == -1) {
			c->outgoing = NULL;
			logger(DEBUG_CONNECTIONS, LOG_INFO, "No more outgoing connection to %s", c->name);
			terminate_connection(c, c->edge);
		}
	}

	/* Delete outgoing_ts for which there is no ConnectTo. */

	for list_each(outgoing_t, outgoing, outgoing_list)
		if(outgoing->timeout == -1)
			list_delete_node(outgoing_list, node);
}
