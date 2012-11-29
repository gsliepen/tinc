/*
    net.h -- header for net.c
    Copyright (C) 1998-2005 Ivo Timmermans
                  2000-2012 Guus Sliepen <guus@tinc-vpn.org>

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

#ifndef __TINC_NET_H__
#define __TINC_NET_H__

#include "ipv6.h"
#include "cipher.h"
#include "digest.h"
#include "event.h"

#ifdef ENABLE_JUMBOGRAMS
#define MTU 9018        /* 9000 bytes payload + 14 bytes ethernet header + 4 bytes VLAN tag */
#else
#define MTU 1518        /* 1500 bytes payload + 14 bytes ethernet header + 4 bytes VLAN tag */
#endif

/* MAXSIZE is the maximum size of an encapsulated packet: MTU + seqno + padding + HMAC + compressor overhead */
#define MAXSIZE (MTU + 4 + CIPHER_MAX_BLOCK_SIZE + DIGEST_MAX_SIZE + MTU/64 + 20)

/* MAXBUFSIZE is the maximum size of a request: enough for a MAXSIZEd packet or a 8192 bits RSA key */
#define MAXBUFSIZE ((MAXSIZE > 2048 ? MAXSIZE : 2048) + 128)

#define MAXSOCKETS 8    /* Probably overkill... */

typedef struct mac_t {
	uint8_t x[6];
} mac_t;

typedef struct ipv4_t {
	uint8_t x[4];
} ipv4_t;

typedef struct ipv6_t {
	uint16_t x[8];
} ipv6_t;

typedef short length_t;

#define AF_UNKNOWN 255

struct sockaddr_unknown {
	uint16_t family;
	uint16_t pad1;
	uint32_t pad2;
	char *address;
	char *port;
};

typedef union sockaddr_t {
	struct sockaddr sa;
	struct sockaddr_in in;
	struct sockaddr_in6 in6;
	struct sockaddr_unknown unknown;
#ifdef HAVE_STRUCT_SOCKADDR_STORAGE
	struct sockaddr_storage storage;
#endif
} sockaddr_t;

#ifdef SA_LEN
#define SALEN(s) SA_LEN(&s)
#else
#define SALEN(s) (s.sa_family==AF_INET?sizeof(struct sockaddr_in):sizeof(struct sockaddr_in6))
#endif

typedef struct vpn_packet_t {
	length_t len;           /* the actual number of bytes in the `data' field */
	int priority;           /* priority or TOS */
	uint32_t seqno;         /* 32 bits sequence number (network byte order of course) */
	uint8_t data[MAXSIZE];
} vpn_packet_t;

/* Packet types when using SPTPS */

#define PKT_COMPRESSED 1
#define PKT_MAC 2
#define PKT_PROBE 4

typedef enum packet_type_t {
	PACKET_NORMAL,
	PACKET_COMPRESSED,
	PACKET_PROBE
} packet_type_t;

typedef struct listen_socket_t {
	io_t tcp;
	io_t udp;
	sockaddr_t sa;
} listen_socket_t;

#include "conf.h"
#include "list.h"

typedef struct outgoing_t {
	char *name;
	int timeout;
	splay_tree_t *config_tree;
	struct config_t *cfg;
	struct addrinfo *ai;
	struct addrinfo *aip;
	timeout_t ev;
} outgoing_t;

extern list_t *outgoing_list;

extern int maxoutbufsize;
extern int seconds_till_retry;
extern int addressfamily;
extern unsigned replaywin;
extern bool localdiscovery;

extern listen_socket_t listen_socket[MAXSOCKETS];
extern int listen_sockets;
extern int keylifetime;
extern int udp_rcvbuf;
extern int udp_sndbuf;
extern bool do_prune;
extern char *myport;
extern int autoconnect;
extern int contradicting_add_edge;
extern int contradicting_del_edge;
extern time_t last_config_check;

extern char *proxyhost;
extern char *proxyport;
extern char *proxyuser;
extern char *proxypass;
typedef enum proxytype_t {
	PROXY_NONE = 0,
	PROXY_SOCKS4,
	PROXY_SOCKS4A,
	PROXY_SOCKS5,
	PROXY_HTTP,
	PROXY_EXEC,
} proxytype_t;
extern proxytype_t proxytype;

extern char *scriptinterpreter;
extern char *scriptextension;

/* Yes, very strange placement indeed, but otherwise the typedefs get all tangled up */
#include "connection.h"
#include "node.h"

extern void retry_outgoing(outgoing_t *);
extern void handle_incoming_vpn_data(void *, int);
extern void finish_connecting(struct connection_t *);
extern bool do_outgoing_connection(struct outgoing_t *);
extern void handle_new_meta_connection(void *, int);
extern int setup_listen_socket(const sockaddr_t *);
extern int setup_vpn_in_socket(const sockaddr_t *);
extern bool send_sptps_data(void *handle, uint8_t type, const char *data, size_t len);
extern bool receive_sptps_record(void *handle, uint8_t type, const char *data, uint16_t len);
extern void send_packet(struct node_t *, vpn_packet_t *);
extern void receive_tcppacket(struct connection_t *, const char *, int);
extern void broadcast_packet(const struct node_t *, vpn_packet_t *);
extern char *get_name(void);
extern bool setup_myself_reloadable(void);
extern bool setup_network(void);
extern void setup_outgoing_connection(struct outgoing_t *);
extern void try_outgoing_connections(void);
extern void close_network_connections(void);
extern int main_loop(void);
extern void terminate_connection(struct connection_t *, bool);
extern bool node_read_ecdsa_public_key(struct node_t *);
extern bool read_ecdsa_public_key(struct connection_t *);
extern bool read_rsa_public_key(struct connection_t *);
extern void send_mtu_probe(struct node_t *);
extern void handle_device_data(void *, int);
extern void handle_meta_connection_data(struct connection_t *);
extern void regenerate_key(void);
extern void purge(void);
extern void retry(void);
extern int reload_configuration(void);
extern void load_all_subnets(void);
extern void load_all_nodes(void);

#ifndef HAVE_MINGW
#define closesocket(s) close(s)
#else
extern CRITICAL_SECTION mutex;
#endif

#endif /* __TINC_NET_H__ */
