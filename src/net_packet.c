/*
    net_packet.c -- Handles in- and outgoing VPN packets
    Copyright (C) 1998-2005 Ivo Timmermans,
                  2000-2011 Guus Sliepen <guus@tinc-vpn.org>
                  2010      Timothy Redaelli <timothy@redaelli.eu>
                  2010      Brandon Black <blblack@gmail.com>

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
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/hmac.h>

#ifdef HAVE_ZLIB
#include <zlib.h>
#endif

#ifdef HAVE_LZO
#include LZO1X_H
#endif

#include "splay_tree.h"
#include "cipher.h"
#include "conf.h"
#include "connection.h"
#include "crypto.h"
#include "digest.h"
#include "device.h"
#include "ethernet.h"
#include "graph.h"
#include "logger.h"
#include "net.h"
#include "netutl.h"
#include "protocol.h"
#include "process.h"
#include "route.h"
#include "utils.h"
#include "xalloc.h"

int keylifetime = 0;
#ifdef HAVE_LZO
static char lzo_wrkmem[LZO1X_999_MEM_COMPRESS > LZO1X_1_MEM_COMPRESS ? LZO1X_999_MEM_COMPRESS : LZO1X_1_MEM_COMPRESS];
#endif

static void send_udppacket(node_t *, vpn_packet_t *);

unsigned replaywin = 16;

#define MAX_SEQNO 1073741824

// mtuprobes == 1..30: initial discovery, send bursts with 1 second interval
// mtuprobes ==    31: sleep pinginterval seconds
// mtuprobes ==    32: send 1 burst, sleep pingtimeout second
// mtuprobes ==    33: no response from other side, restart PMTU discovery process

static void send_mtu_probe_handler(int fd, short events, void *data) {
	node_t *n = data;
	vpn_packet_t packet;
	int len, i;
	int timeout = 1;
	
	n->mtuprobes++;

	if(!n->status.reachable || !n->status.validkey) {
		ifdebug(TRAFFIC) logger(LOG_INFO, "Trying to send MTU probe to unreachable or rekeying node %s (%s)", n->name, n->hostname);
		n->mtuprobes = 0;
		return;
	}

	if(n->mtuprobes > 32) {
		if(!n->minmtu) {
			n->mtuprobes = 31;
			timeout = pinginterval;
			goto end;
		}

		ifdebug(TRAFFIC) logger(LOG_INFO, "%s (%s) did not respond to UDP ping, restarting PMTU discovery", n->name, n->hostname);
		n->mtuprobes = 1;
		n->minmtu = 0;
		n->maxmtu = MTU;
	}

	if(n->mtuprobes >= 10 && n->mtuprobes < 32 && !n->minmtu) {
		ifdebug(TRAFFIC) logger(LOG_INFO, "No response to MTU probes from %s (%s)", n->name, n->hostname);
		n->mtuprobes = 31;
	}

	if(n->mtuprobes == 30 || (n->mtuprobes < 30 && n->minmtu >= n->maxmtu)) {
		if(n->minmtu > n->maxmtu)
			n->minmtu = n->maxmtu;
		else
			n->maxmtu = n->minmtu;
		n->mtu = n->minmtu;
		ifdebug(TRAFFIC) logger(LOG_INFO, "Fixing MTU of %s (%s) to %d after %d probes", n->name, n->hostname, n->mtu, n->mtuprobes);
		n->mtuprobes = 31;
	}

	if(n->mtuprobes == 31) {
		timeout = pinginterval;
		goto end;
	} else if(n->mtuprobes == 32) {
		timeout = pingtimeout;
	}

	for(i = 0; i < 3; i++) {
		if(n->maxmtu <= n->minmtu)
			len = n->maxmtu;
		else
			len = n->minmtu + 1 + rand() % (n->maxmtu - n->minmtu);

		if(len < 64)
			len = 64;
		
		memset(packet.data, 0, 14);
		randomize(packet.data + 14, len - 14);
		packet.len = len;
		packet.priority = 0;

		ifdebug(TRAFFIC) logger(LOG_INFO, "Sending MTU probe length %d to %s (%s)", len, n->name, n->hostname);

		send_udppacket(n, &packet);
	}

end:
	event_add(&n->mtuevent, &(struct timeval){timeout, 0});
}

void send_mtu_probe(node_t *n) {
	if(!timeout_initialized(&n->mtuevent))
		timeout_set(&n->mtuevent, send_mtu_probe_handler, n);
	send_mtu_probe_handler(0, 0, n);
}

static void mtu_probe_h(node_t *n, vpn_packet_t *packet, length_t len) {
	ifdebug(TRAFFIC) logger(LOG_INFO, "Got MTU probe length %d from %s (%s)", packet->len, n->name, n->hostname);

	if(!packet->data[0]) {
		packet->data[0] = 1;
		send_udppacket(n, packet);
	} else {
		if(n->mtuprobes > 30) {
			if(n->minmtu)
				n->mtuprobes = 30;
			else
				n->mtuprobes = 1;
		}

		if(len > n->maxmtu)
			len = n->maxmtu;
		if(n->minmtu < len)
			n->minmtu = len;
	}
}

static length_t compress_packet(uint8_t *dest, const uint8_t *source, length_t len, int level) {
	if(level == 0) {
		memcpy(dest, source, len);
		return len;
	} else if(level == 10) {
#ifdef HAVE_LZO
		lzo_uint lzolen = MAXSIZE;
		lzo1x_1_compress(source, len, dest, &lzolen, lzo_wrkmem);
		return lzolen;
#else
		return -1;
#endif
	} else if(level < 10) {
#ifdef HAVE_ZLIB
		unsigned long destlen = MAXSIZE;
		if(compress2(dest, &destlen, source, len, level) == Z_OK)
			return destlen;
		else
#endif
			return -1;
	} else {
#ifdef HAVE_LZO
		lzo_uint lzolen = MAXSIZE;
		lzo1x_999_compress(source, len, dest, &lzolen, lzo_wrkmem);
		return lzolen;
#else
		return -1;
#endif
	}
	
	return -1;
}

static length_t uncompress_packet(uint8_t *dest, const uint8_t *source, length_t len, int level) {
	if(level == 0) {
		memcpy(dest, source, len);
		return len;
	} else if(level > 9) {
#ifdef HAVE_LZO
		lzo_uint lzolen = MAXSIZE;
		if(lzo1x_decompress_safe(source, len, dest, &lzolen, NULL) == LZO_E_OK)
			return lzolen;
		else
#endif
			return -1;
	}
#ifdef HAVE_ZLIB
	else {
		unsigned long destlen = MAXSIZE;
		if(uncompress(dest, &destlen, source, len) == Z_OK)
			return destlen;
		else
			return -1;
	}
#endif

	return -1;
}

/* VPN packet I/O */

static void receive_packet(node_t *n, vpn_packet_t *packet) {
	ifdebug(TRAFFIC) logger(LOG_DEBUG, "Received packet of %d bytes from %s (%s)",
			   packet->len, n->name, n->hostname);

	n->in_packets++;
	n->in_bytes += packet->len;

	route(n, packet);
}

static bool try_mac(node_t *n, const vpn_packet_t *inpkt) {
	if(!digest_active(&n->indigest) || inpkt->len < sizeof inpkt->seqno + digest_length(&n->indigest))
		return false;

	return digest_verify(&n->indigest, &inpkt->seqno, inpkt->len - n->indigest.maclength, (const char *)&inpkt->seqno + inpkt->len - n->indigest.maclength);
}

static void receive_udppacket(node_t *n, vpn_packet_t *inpkt) {
	vpn_packet_t pkt1, pkt2;
	vpn_packet_t *pkt[] = { &pkt1, &pkt2, &pkt1, &pkt2 };
	int nextpkt = 0;
	vpn_packet_t *outpkt = pkt[0];
	size_t outlen;

	if(!cipher_active(&n->incipher)) {
		ifdebug(TRAFFIC) logger(LOG_DEBUG, "Got packet from %s (%s) but he hasn't got our key yet",
					n->name, n->hostname);
		return;
	}

	/* Check packet length */

	if(inpkt->len < sizeof inpkt->seqno + digest_length(&n->indigest)) {
		ifdebug(TRAFFIC) logger(LOG_DEBUG, "Got too short packet from %s (%s)",
					n->name, n->hostname);
		return;
	}

	/* Check the message authentication code */

	if(digest_active(&n->indigest)) {
		inpkt->len -= n->indigest.maclength;
 		if(!digest_verify(&n->indigest, &inpkt->seqno, inpkt->len, (const char *)&inpkt->seqno + inpkt->len)) {
			ifdebug(TRAFFIC) logger(LOG_DEBUG, "Got unauthenticated packet from %s (%s)", n->name, n->hostname);
			return;
		}
	}
	/* Decrypt the packet */

	if(cipher_active(&n->incipher)) {
		outpkt = pkt[nextpkt++];
		outlen = MAXSIZE;

		if(!cipher_decrypt(&n->incipher, &inpkt->seqno, inpkt->len, &outpkt->seqno, &outlen, true)) {
			ifdebug(TRAFFIC) logger(LOG_DEBUG, "Error decrypting packet from %s (%s)", n->name, n->hostname);
			return;
		}
		
		outpkt->len = outlen;
		inpkt = outpkt;
	}

	/* Check the sequence number */

	inpkt->len -= sizeof inpkt->seqno;
	inpkt->seqno = ntohl(inpkt->seqno);

	if(replaywin) {
		if(inpkt->seqno != n->received_seqno + 1) {
			if(inpkt->seqno >= n->received_seqno + replaywin * 8) {
				if(n->farfuture++ < replaywin >> 2) {
					logger(LOG_WARNING, "Packet from %s (%s) is %d seqs in the future, dropped (%u)",
						n->name, n->hostname, inpkt->seqno - n->received_seqno - 1, n->farfuture);
					return;
				}
				logger(LOG_WARNING, "Lost %d packets from %s (%s)",
					   	inpkt->seqno - n->received_seqno - 1, n->name, n->hostname);
				memset(n->late, 0, replaywin);
			} else if (inpkt->seqno <= n->received_seqno) {
				if((n->received_seqno >= replaywin * 8 && inpkt->seqno <= n->received_seqno - replaywin * 8) || !(n->late[(inpkt->seqno / 8) % replaywin] & (1 << inpkt->seqno % 8))) {
					logger(LOG_WARNING, "Got late or replayed packet from %s (%s), seqno %d, last received %d",
					   	n->name, n->hostname, inpkt->seqno, n->received_seqno);
					return;
				}
			} else {
				for(int i = n->received_seqno + 1; i < inpkt->seqno; i++)
					n->late[(i / 8) % replaywin] |= 1 << i % 8;
			}
		}

		n->farfuture = 0;
		n->late[(inpkt->seqno / 8) % replaywin] &= ~(1 << inpkt->seqno % 8);
	}

	if(inpkt->seqno > n->received_seqno)
		n->received_seqno = inpkt->seqno;
			
	if(n->received_seqno > MAX_SEQNO)
		regenerate_key();

	/* Decompress the packet */

	length_t origlen = inpkt->len;

	if(n->incompression) {
		outpkt = pkt[nextpkt++];

		if((outpkt->len = uncompress_packet(outpkt->data, inpkt->data, inpkt->len, n->incompression)) < 0) {
			ifdebug(TRAFFIC) logger(LOG_ERR, "Error while uncompressing packet from %s (%s)",
				  		 n->name, n->hostname);
			return;
		}

		inpkt = outpkt;

		origlen -= MTU/64 + 20;
	}

	inpkt->priority = 0;

	if(!inpkt->data[12] && !inpkt->data[13])
		mtu_probe_h(n, inpkt, origlen);
	else
		receive_packet(n, inpkt);
}

void receive_tcppacket(connection_t *c, const char *buffer, int len) {
	vpn_packet_t outpkt;

	outpkt.len = len;
	if(c->options & OPTION_TCPONLY)
		outpkt.priority = 0;
	else
		outpkt.priority = -1;
	memcpy(outpkt.data, buffer, len);

	receive_packet(c->node, &outpkt);
}

static void send_udppacket(node_t *n, vpn_packet_t *origpkt) {
	vpn_packet_t pkt1, pkt2;
	vpn_packet_t *pkt[] = { &pkt1, &pkt2, &pkt1, &pkt2 };
	vpn_packet_t *inpkt = origpkt;
	int nextpkt = 0;
	vpn_packet_t *outpkt;
	int origlen = origpkt->len;
	size_t outlen;
#if defined(SOL_IP) && defined(IP_TOS)
	static int priority = 0;
	int origpriority = origpkt->priority;
#endif
	int sock;

	if(!n->status.reachable) {
		ifdebug(TRAFFIC) logger(LOG_INFO, "Trying to send UDP packet to unreachable node %s (%s)", n->name, n->hostname);
		return;
	}

	/* Make sure we have a valid key */

	if(!n->status.validkey) {
		time_t now = time(NULL);

		ifdebug(TRAFFIC) logger(LOG_INFO,
				   "No valid key known yet for %s (%s), forwarding via TCP",
				   n->name, n->hostname);

		if(n->last_req_key + 10 <= now) {
			send_req_key(n);
			n->last_req_key = now;
		}

		send_tcppacket(n->nexthop->connection, origpkt);

		return;
	}

	if(n->options & OPTION_PMTU_DISCOVERY && inpkt->len > n->minmtu && (inpkt->data[12] | inpkt->data[13])) {
		ifdebug(TRAFFIC) logger(LOG_INFO,
				"Packet for %s (%s) larger than minimum MTU, forwarding via %s",
				n->name, n->hostname, n != n->nexthop ? n->nexthop->name : "TCP");

		if(n != n->nexthop)
			send_packet(n->nexthop, origpkt);
		else
			send_tcppacket(n->nexthop->connection, origpkt);

		return;
	}

	/* Compress the packet */

	if(n->outcompression) {
		outpkt = pkt[nextpkt++];

		if((outpkt->len = compress_packet(outpkt->data, inpkt->data, inpkt->len, n->outcompression)) < 0) {
			ifdebug(TRAFFIC) logger(LOG_ERR, "Error while compressing packet to %s (%s)",
				   n->name, n->hostname);
			return;
		}

		inpkt = outpkt;
	}

	/* Add sequence number */

	inpkt->seqno = htonl(++(n->sent_seqno));
	inpkt->len += sizeof inpkt->seqno;

	/* Encrypt the packet */

	if(cipher_active(&n->outcipher)) {
		outpkt = pkt[nextpkt++];
		outlen = MAXSIZE;

		if(!cipher_encrypt(&n->outcipher, &inpkt->seqno, inpkt->len, &outpkt->seqno, &outlen, true)) {
			ifdebug(TRAFFIC) logger(LOG_ERR, "Error while encrypting packet to %s (%s)", n->name, n->hostname);
			goto end;
		}

		outpkt->len = outlen;
		inpkt = outpkt;
	}

	/* Add the message authentication code */

	if(digest_active(&n->outdigest)) {
		digest_create(&n->outdigest, &inpkt->seqno, inpkt->len, (char *)&inpkt->seqno + inpkt->len);
		inpkt->len += digest_length(&n->outdigest);
	}

	/* Determine which socket we have to use */

	for(sock = 0; sock < listen_sockets; sock++)
		if(n->address.sa.sa_family == listen_socket[sock].sa.sa.sa_family)
			break;

	if(sock >= listen_sockets)
		sock = 0;				/* If none is available, just use the first and hope for the best. */

	/* Send the packet */

#if defined(SOL_IP) && defined(IP_TOS)
	if(priorityinheritance && origpriority != priority
	   && listen_socket[sock].sa.sa.sa_family == AF_INET) {
		priority = origpriority;
		ifdebug(TRAFFIC) logger(LOG_DEBUG, "Setting outgoing packet priority to %d", priority);
		if(setsockopt(listen_socket[sock].udp, SOL_IP, IP_TOS, &priority, sizeof priority))	/* SO_PRIORITY doesn't seem to work */
			logger(LOG_ERR, "System call `%s' failed: %s", "setsockopt", strerror(errno));
	}
#endif

	if(sendto(listen_socket[sock].udp, (char *) &inpkt->seqno, inpkt->len, 0, &(n->address.sa), SALEN(n->address.sa)) < 0 && !sockwouldblock(sockerrno)) {
		if(sockmsgsize(sockerrno)) {
			if(n->maxmtu >= origlen)
				n->maxmtu = origlen - 1;
			if(n->mtu >= origlen)
				n->mtu = origlen - 1;
		} else
			logger(LOG_ERR, "Error sending packet to %s (%s): %s", n->name, n->hostname, sockstrerror(sockerrno));
	}

end:
	origpkt->len = origlen;
}

/*
  send a packet to the given vpn ip.
*/
void send_packet(node_t *n, vpn_packet_t *packet) {
	node_t *via;

	if(n == myself) {
		if(overwrite_mac)
			 memcpy(packet->data, mymac.x, ETH_ALEN);
		n->out_packets++;
		n->out_bytes += packet->len;
		write_packet(packet);
		return;
	}

	ifdebug(TRAFFIC) logger(LOG_ERR, "Sending packet of %d bytes to %s (%s)",
			   packet->len, n->name, n->hostname);

	if(!n->status.reachable) {
		ifdebug(TRAFFIC) logger(LOG_INFO, "Node %s (%s) is not reachable",
				   n->name, n->hostname);
		return;
	}

	n->out_packets++;
	n->out_bytes += packet->len;

	via = (packet->priority == -1 || n->via == myself) ? n->nexthop : n->via;

	if(via != n)
		ifdebug(TRAFFIC) logger(LOG_INFO, "Sending packet to %s via %s (%s)",
			   n->name, via->name, n->via->hostname);

	if(packet->priority == -1 || ((myself->options | via->options) & OPTION_TCPONLY)) {
		if(!send_tcppacket(via->connection, packet))
			terminate_connection(via->connection, true);
	} else
		send_udppacket(via, packet);
}

/* Broadcast a packet using the minimum spanning tree */

void broadcast_packet(const node_t *from, vpn_packet_t *packet) {
	splay_node_t *node;
	connection_t *c;

	ifdebug(TRAFFIC) logger(LOG_INFO, "Broadcasting packet of %d bytes from %s (%s)",
			   packet->len, from->name, from->hostname);

	if(from != myself) {
		send_packet(myself, packet);

		// In TunnelServer mode, do not forward broadcast packets.
                // The MST might not be valid and create loops.
		if(tunnelserver)
			return;
	}

	for(node = connection_tree->head; node; node = node->next) {
		c = node->data;

		if(c->status.active && c->status.mst && c != from->nexthop->connection)
			send_packet(c->node, packet);
	}
}

static node_t *try_harder(const sockaddr_t *from, const vpn_packet_t *pkt) {
	splay_node_t *node;
	edge_t *e;
	node_t *n = NULL;
	bool hard = false;
	static time_t last_hard_try = 0;
	time_t now = time(NULL);

	if(last_hard_try == now)
		return NULL;
	else
		last_hard_try = now;

	for(node = edge_weight_tree->head; node; node = node->next) {
		e = node->data;

		if(e->to == myself)
			continue;

		if(sockaddrcmp_noport(from, &e->address)) {
			if(last_hard_try == now)
				continue;
			hard = true;
		}

		if(!try_mac(e->to, pkt))
			continue;

		n = e->to;
		break;
	}

	if(hard)
		last_hard_try = now;

	return n;
}

void handle_incoming_vpn_data(int sock, short events, void *data) {
	vpn_packet_t pkt;
	char *hostname;
	sockaddr_t from;
	socklen_t fromlen = sizeof from;
	node_t *n;
	int len;

	len = recvfrom(sock, (char *) &pkt.seqno, MAXSIZE, 0, &from.sa, &fromlen);

	if(len <= 0 || len > MAXSIZE) {
		if(!sockwouldblock(sockerrno))
			logger(LOG_ERR, "Receiving packet failed: %s", sockstrerror(sockerrno));
		return;
	}

	pkt.len = len;

	sockaddrunmap(&from);		/* Some braindead IPv6 implementations do stupid things. */

	n = lookup_node_udp(&from);

	if(!n) {
		n = try_harder(&from, &pkt);
		if(n)
			update_node_udp(n, &from);
		else ifdebug(PROTOCOL) {
			hostname = sockaddr2hostname(&from);
			logger(LOG_WARNING, "Received UDP packet from unknown source %s", hostname);
			free(hostname);
			return;
		}
		else
			return;
	}

	receive_udppacket(n, &pkt);
}

void handle_device_data(int sock, short events, void *data) {
	vpn_packet_t packet;

	packet.priority = 0;

	if(read_packet(&packet)) {
		myself->in_packets++;
		myself->in_bytes += packet.len;
		route(myself, &packet);
	}
}
