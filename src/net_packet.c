/*
    net_packet.c -- Handles in- and outgoing VPN packets
    Copyright (C) 1998-2005 Ivo Timmermans,
                  2000-2014 Guus Sliepen <guus@tinc-vpn.org>
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

#ifdef HAVE_ZLIB
#include <zlib.h>
#endif

#ifdef HAVE_LZO
#include LZO1X_H
#endif

#include "cipher.h"
#include "conf.h"
#include "connection.h"
#include "crypto.h"
#include "digest.h"
#include "device.h"
#include "ethernet.h"
#include "ipv4.h"
#include "ipv6.h"
#include "graph.h"
#include "logger.h"
#include "net.h"
#include "netutl.h"
#include "protocol.h"
#include "route.h"
#include "utils.h"
#include "xalloc.h"

#ifndef MAX
#define MAX(a, b) ((a) > (b) ? (a) : (b))
#endif

/* The minimum size of a probe is 14 bytes, but since we normally use CBC mode
   encryption, we can add a few extra random bytes without increasing the
   resulting packet size. */
#define MIN_PROBE_SIZE 18

int keylifetime = 0;
int edgeupdateinterval = 0;
#ifdef HAVE_LZO
static char lzo_wrkmem[LZO1X_999_MEM_COMPRESS > LZO1X_1_MEM_COMPRESS ? LZO1X_999_MEM_COMPRESS : LZO1X_1_MEM_COMPRESS];
#endif

static void send_udppacket(node_t *, vpn_packet_t *);

unsigned replaywin = 32;
bool localdiscovery = true;
bool udp_discovery = true;
int udp_discovery_keepalive_interval = 10;
int udp_discovery_interval = 2;
int udp_discovery_timeout = 30;

#define MAX_SEQNO 1073741824

static void try_fix_mtu(node_t *n) {
	if(n->mtuprobes < 0)
		return;

	if(n->mtuprobes == 20 || n->minmtu >= n->maxmtu) {
		if(n->minmtu > n->maxmtu)
			n->minmtu = n->maxmtu;
		else
			n->maxmtu = n->minmtu;
		n->mtu = n->minmtu;
		logger(DEBUG_TRAFFIC, LOG_INFO, "Fixing MTU of %s (%s) to %d after %d probes", n->name, n->hostname, n->mtu, n->mtuprobes);
		n->mtuprobes = -1;
	}
}

static void udp_probe_timeout_handler(void *data) {
	node_t *n = data;
	if(!n->status.udp_confirmed)
		return;

	logger(DEBUG_TRAFFIC, LOG_INFO, "Too much time has elapsed since last UDP ping response from %s (%s), stopping UDP communication", n->name, n->hostname);
	n->status.udp_confirmed = false;
	n->maxrecentlen = 0;
	n->mtuprobes = 0;
	n->minmtu = 0;
	n->maxmtu = MTU;
}

static void send_udp_probe_reply(node_t *n, vpn_packet_t *packet, length_t len) {
	if(!n->status.sptps && !n->status.validkey) {
		logger(DEBUG_TRAFFIC, LOG_INFO, "Trying to send UDP probe reply to %s (%s) but we don't have his key yet", n->name, n->hostname);
		return;
	}

	/* Type 2 probe replies were introduced in protocol 17.3 */
	if ((n->options >> 24) >= 3) {
		DATA(packet)[0] = 2;
		uint16_t len16 = htons(len);
		memcpy(DATA(packet) + 1, &len16, 2);
		packet->len = MIN_PROBE_SIZE;
		logger(DEBUG_TRAFFIC, LOG_INFO, "Sending type 2 probe reply length %u to %s (%s)", len, n->name, n->hostname);

	} else {
		/* Legacy protocol: n won't understand type 2 probe replies. */
		DATA(packet)[0] = 1;
		logger(DEBUG_TRAFFIC, LOG_INFO, "Sending type 1 probe reply length %u to %s (%s)", len, n->name, n->hostname);
	}

	/* Temporarily set udp_confirmed, so that the reply is sent
	   back exactly the way it came in. */

	bool udp_confirmed = n->status.udp_confirmed;
	n->status.udp_confirmed = true;
	send_udppacket(n, packet);
	n->status.udp_confirmed = udp_confirmed;
}

static void udp_probe_h(node_t *n, vpn_packet_t *packet, length_t len) {
	if(!DATA(packet)[0]) {
		logger(DEBUG_TRAFFIC, LOG_INFO, "Got UDP probe request %d from %s (%s)", packet->len, n->name, n->hostname);
		return send_udp_probe_reply(n, packet, len);
	}

	if (DATA(packet)[0] == 2) {
		// It's a type 2 probe reply, use the length field inside the packet
		uint16_t len16;
		memcpy(&len16, DATA(packet) + 1, 2);
		len = ntohs(len16);
	}

	logger(DEBUG_TRAFFIC, LOG_INFO, "Got type %d UDP probe reply %d from %s (%s)", DATA(packet)[0], len, n->name, n->hostname);

	/* It's a valid reply: now we know bidirectional communication
	   is possible using the address and socket that the reply
	   packet used. */
	n->status.udp_confirmed = true;

	// Reset the UDP ping timer.
	n->udp_ping_sent = now;

	if(udp_discovery) {
		timeout_del(&n->udp_ping_timeout);
		timeout_add(&n->udp_ping_timeout, &udp_probe_timeout_handler, n, &(struct timeval){udp_discovery_timeout, 0});
	}

	if(len > n->maxmtu) {
		logger(DEBUG_TRAFFIC, LOG_INFO, "Increase in PMTU to %s (%s) detected, restarting PMTU discovery", n->name, n->hostname);
		n->minmtu = len;
		n->maxmtu = MTU;
		/* Set mtuprobes to 1 so that try_mtu() doesn't reset maxmtu */
		n->mtuprobes = 1;
		return;
	} else if(n->mtuprobes < 0 && len == n->maxmtu) {
		/* We got a maxmtu sized packet, confirming the PMTU is still valid. */
		n->mtuprobes = -1;
		n->mtu_ping_sent = now;
	}

	/* If applicable, raise the minimum supported MTU */

	if(n->minmtu < len) {
		n->minmtu = len;
		try_fix_mtu(n);
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
	logger(DEBUG_TRAFFIC, LOG_DEBUG, "Received packet of %d bytes from %s (%s)",
			   packet->len, n->name, n->hostname);

	n->in_packets++;
	n->in_bytes += packet->len;

	route(n, packet);
}

static bool try_mac(node_t *n, const vpn_packet_t *inpkt) {
	if(n->status.sptps)
		return sptps_verify_datagram(&n->sptps, DATA(inpkt), inpkt->len);

#ifdef DISABLE_LEGACY
	return false;
#else
	if(!n->status.validkey_in || !digest_active(n->indigest) || inpkt->len < sizeof(seqno_t) + digest_length(n->indigest))
		return false;

	return digest_verify(n->indigest, (inpkt)->data + (inpkt)->offset, inpkt->len - digest_length(n->indigest), DATA(inpkt) + inpkt->len - digest_length(n->indigest));
#endif
}

static bool receive_udppacket(node_t *n, vpn_packet_t *inpkt) {
	vpn_packet_t pkt1, pkt2;
	vpn_packet_t *pkt[] = { &pkt1, &pkt2, &pkt1, &pkt2 };
	int nextpkt = 0;
	size_t outlen;
	pkt1.offset = DEFAULT_PACKET_OFFSET;
	pkt2.offset = DEFAULT_PACKET_OFFSET;

	if(n->status.sptps) {
		if(!n->sptps.state) {
			if(!n->status.waitingforkey) {
				logger(DEBUG_TRAFFIC, LOG_DEBUG, "Got packet from %s (%s) but we haven't exchanged keys yet", n->name, n->hostname);
				send_req_key(n);
			} else {
				logger(DEBUG_TRAFFIC, LOG_DEBUG, "Got packet from %s (%s) but he hasn't got our key yet", n->name, n->hostname);
			}
			return false;
		}
		inpkt->offset += 2 * sizeof(node_id_t);
		n->status.udppacket = true;
		bool result = sptps_receive_data(&n->sptps, DATA(inpkt), inpkt->len - 2 * sizeof(node_id_t));
		n->status.udppacket = false;

		if(!result) {
			logger(DEBUG_TRAFFIC, LOG_ERR, "Got bad packet from %s (%s)", n->name, n->hostname);
			return false;
		}
		return true;
	}

#ifdef DISABLE_LEGACY
	return false;
#else
	if(!n->status.validkey_in) {
		logger(DEBUG_TRAFFIC, LOG_DEBUG, "Got packet from %s (%s) but he hasn't got our key yet", n->name, n->hostname);
		return false;
	}

	/* Check packet length */

	if(inpkt->len < sizeof(seqno_t) + digest_length(n->indigest)) {
		logger(DEBUG_TRAFFIC, LOG_DEBUG, "Got too short packet from %s (%s)",
					n->name, n->hostname);
		return false;
	}

	/* It's a legacy UDP packet, the data starts after the seqno */

	inpkt->offset += sizeof(seqno_t);

	/* Check the message authentication code */

	if(digest_active(n->indigest)) {
		inpkt->len -= digest_length(n->indigest);
		if(!digest_verify(n->indigest, SEQNO(inpkt), inpkt->len, SEQNO(inpkt) + inpkt->len)) {
			logger(DEBUG_TRAFFIC, LOG_DEBUG, "Got unauthenticated packet from %s (%s)", n->name, n->hostname);
			return false;
		}
	}
	/* Decrypt the packet */

	if(cipher_active(n->incipher)) {
		vpn_packet_t *outpkt = pkt[nextpkt++];
		outlen = MAXSIZE;

		if(!cipher_decrypt(n->incipher, SEQNO(inpkt), inpkt->len, SEQNO(outpkt), &outlen, true)) {
			logger(DEBUG_TRAFFIC, LOG_DEBUG, "Error decrypting packet from %s (%s)", n->name, n->hostname);
			return false;
		}

		outpkt->len = outlen;
		inpkt = outpkt;
	}

	/* Check the sequence number */

	seqno_t seqno;
	memcpy(&seqno, SEQNO(inpkt), sizeof seqno);
	seqno = ntohl(seqno);
	inpkt->len -= sizeof seqno;

	if(replaywin) {
		if(seqno != n->received_seqno + 1) {
			if(seqno >= n->received_seqno + replaywin * 8) {
				if(n->farfuture++ < replaywin >> 2) {
					logger(DEBUG_ALWAYS, LOG_WARNING, "Packet from %s (%s) is %d seqs in the future, dropped (%u)",
						n->name, n->hostname, seqno - n->received_seqno - 1, n->farfuture);
					return false;
				}
				logger(DEBUG_ALWAYS, LOG_WARNING, "Lost %d packets from %s (%s)",
						seqno - n->received_seqno - 1, n->name, n->hostname);
				memset(n->late, 0, replaywin);
			} else if (seqno <= n->received_seqno) {
				if((n->received_seqno >= replaywin * 8 && seqno <= n->received_seqno - replaywin * 8) || !(n->late[(seqno / 8) % replaywin] & (1 << seqno % 8))) {
					logger(DEBUG_ALWAYS, LOG_WARNING, "Got late or replayed packet from %s (%s), seqno %d, last received %d",
						n->name, n->hostname, seqno, n->received_seqno);
					return false;
				}
			} else {
				for(int i = n->received_seqno + 1; i < seqno; i++)
					n->late[(i / 8) % replaywin] |= 1 << i % 8;
			}
		}

		n->farfuture = 0;
		n->late[(seqno / 8) % replaywin] &= ~(1 << seqno % 8);
	}

	if(seqno > n->received_seqno)
		n->received_seqno = seqno;

	n->received++;

	if(n->received_seqno > MAX_SEQNO)
		regenerate_key();

	/* Decompress the packet */

	length_t origlen = inpkt->len;

	if(n->incompression) {
		vpn_packet_t *outpkt = pkt[nextpkt++];

		if((outpkt->len = uncompress_packet(DATA(outpkt), DATA(inpkt), inpkt->len, n->incompression)) < 0) {
			logger(DEBUG_TRAFFIC, LOG_ERR, "Error while uncompressing packet from %s (%s)",
						 n->name, n->hostname);
			return false;
		}

		inpkt = outpkt;

		origlen -= MTU/64 + 20;
	}

	if(inpkt->len > n->maxrecentlen)
		n->maxrecentlen = inpkt->len;

	inpkt->priority = 0;

	if(!DATA(inpkt)[12] && !DATA(inpkt)[13])
		udp_probe_h(n, inpkt, origlen);
	else
		receive_packet(n, inpkt);
	return true;
#endif
}

void receive_tcppacket(connection_t *c, const char *buffer, int len) {
	vpn_packet_t outpkt;
	outpkt.offset = DEFAULT_PACKET_OFFSET;

	if(len > sizeof outpkt.data - outpkt.offset)
		return;

	outpkt.len = len;
	if(c->options & OPTION_TCPONLY)
		outpkt.priority = 0;
	else
		outpkt.priority = -1;
	memcpy(DATA(&outpkt), buffer, len);

	receive_packet(c->node, &outpkt);
}

bool receive_tcppacket_sptps(connection_t *c, const char *data, int len) {
	if (len < sizeof(node_id_t) + sizeof(node_id_t)) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Got too short TCP SPTPS packet from %s (%s)", c->name, c->hostname);
		return false;
	}

	node_t *to = lookup_node_id((node_id_t *)data);
	data += sizeof(node_id_t); len -= sizeof(node_id_t);
	if(!to) {
		logger(DEBUG_PROTOCOL, LOG_ERR, "Got TCP SPTPS packet from %s (%s) with unknown destination ID", c->name, c->hostname);
		return true;
	}

	node_t *from = lookup_node_id((node_id_t *)data);
	data += sizeof(node_id_t); len -= sizeof(node_id_t);
	if(!from) {
		logger(DEBUG_PROTOCOL, LOG_ERR, "Got TCP SPTPS packet from %s (%s) with unknown source ID", c->name, c->hostname);
		return true;
	}

	/* Help the sender reach us over UDP.
	   Note that we only do this if we're the destination or the static relay;
	   otherwise every hop would initiate its own UDP info message, resulting in elevated chatter. */
	if(to->via == myself)
		send_udp_info(myself, from);

	/* If we're not the final recipient, relay the packet. */

	if(to != myself) {
		send_sptps_data(to, from, 0, data, len);
		try_tx(to, true);
		return true;
	}

	/* The packet is for us */

	if(!from->status.validkey) {
		logger(DEBUG_PROTOCOL, LOG_ERR, "Got SPTPS packet from %s (%s) but we don't have a valid key yet", from->name, from->hostname);
		return true;
	}
	sptps_receive_data(&from->sptps, data, len);
	send_mtu_info(myself, from, MTU);
	return true;
}

static void send_sptps_packet(node_t *n, vpn_packet_t *origpkt) {
	if(!n->status.validkey && !n->connection)
		return;

	uint8_t type = 0;
	int offset = 0;

	if(!(DATA(origpkt)[12] | DATA(origpkt)[13])) {
		sptps_send_record(&n->sptps, PKT_PROBE, (char *)DATA(origpkt), origpkt->len);
		return;
	}

	if(routing_mode == RMODE_ROUTER)
		offset = 14;
	else
		type = PKT_MAC;

	if(origpkt->len < offset)
		return;

	vpn_packet_t outpkt;

	if(n->outcompression) {
		outpkt.offset = 0;
		int len = compress_packet(DATA(&outpkt) + offset, DATA(origpkt) + offset, origpkt->len - offset, n->outcompression);
		if(len < 0) {
			logger(DEBUG_TRAFFIC, LOG_ERR, "Error while compressing packet to %s (%s)", n->name, n->hostname);
		} else if(len < origpkt->len - offset) {
			outpkt.len = len + offset;
			origpkt = &outpkt;
			type |= PKT_COMPRESSED;
		}
	}

	/* If we have a direct metaconnection to n, and we can't use UDP, then
	   don't bother with SPTPS and just use a "plaintext" PACKET message.
	   We don't really care about end-to-end security since we're not
	   sending the message through any intermediate nodes. */
	if(n->connection && origpkt->len > n->minmtu)
		send_tcppacket(n->connection, origpkt);
	else
		sptps_send_record(&n->sptps, type, DATA(origpkt) + offset, origpkt->len - offset);
	return;
}

static void adapt_socket(const sockaddr_t *sa, int *sock) {
	/* Make sure we have a suitable socket for the chosen address */
	if(listen_socket[*sock].sa.sa.sa_family != sa->sa.sa_family) {
		for(int i = 0; i < listen_sockets; i++) {
			if(listen_socket[i].sa.sa.sa_family == sa->sa.sa_family) {
				*sock = i;
				break;
			}
		}
	}
}

static void choose_udp_address(const node_t *n, const sockaddr_t **sa, int *sock) {
	/* Latest guess */
	*sa = &n->address;
	*sock = n->sock;

	/* If the UDP address is confirmed, use it. */
	if(n->status.udp_confirmed)
		return;

	/* Send every third packet to n->address; that could be set
	   to the node's reflexive UDP address discovered during key
	   exchange. */

	static int x = 0;
	if(++x >= 3) {
		x = 0;
		return;
	}

	/* Otherwise, address are found in edges to this node.
	   So we pick a random edge and a random socket. */

	int i = 0;
	int j = rand() % n->edge_tree->count;
	edge_t *candidate = NULL;

	for splay_each(edge_t, e, n->edge_tree) {
		if(i++ == j) {
			candidate = e->reverse;
			break;
		}
	}

	if(candidate) {
		*sa = &candidate->address;
		*sock = rand() % listen_sockets;
	}

	adapt_socket(*sa, sock);
}

static void choose_local_address(const node_t *n, const sockaddr_t **sa, int *sock) {
	*sa = NULL;

	/* Pick one of the edges from this node at random, then use its local address. */

	int i = 0;
	int j = rand() % n->edge_tree->count;
	edge_t *candidate = NULL;

	for splay_each(edge_t, e, n->edge_tree) {
		if(i++ == j) {
			candidate = e;
			break;
		}
	}

	if (candidate && candidate->local_address.sa.sa_family) {
		*sa = &candidate->local_address;
		*sock = rand() % listen_sockets;
		adapt_socket(*sa, sock);
	}
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

	pkt1.offset = DEFAULT_PACKET_OFFSET;
	pkt2.offset = DEFAULT_PACKET_OFFSET;

	if(!n->status.reachable) {
		logger(DEBUG_TRAFFIC, LOG_INFO, "Trying to send UDP packet to unreachable node %s (%s)", n->name, n->hostname);
		return;
	}

	if(n->status.sptps)
		return send_sptps_packet(n, origpkt);

#ifdef DISABLE_LEGACY
	return;
#else
	/* Make sure we have a valid key */

	if(!n->status.validkey) {
		logger(DEBUG_TRAFFIC, LOG_INFO,
				   "No valid key known yet for %s (%s), forwarding via TCP",
				   n->name, n->hostname);
		send_tcppacket(n->nexthop->connection, origpkt);
		return;
	}

	if(n->options & OPTION_PMTU_DISCOVERY && inpkt->len > n->minmtu && (DATA(inpkt)[12] | DATA(inpkt)[13])) {
		logger(DEBUG_TRAFFIC, LOG_INFO,
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

		if((outpkt->len = compress_packet(DATA(outpkt), DATA(inpkt), inpkt->len, n->outcompression)) < 0) {
			logger(DEBUG_TRAFFIC, LOG_ERR, "Error while compressing packet to %s (%s)",
				   n->name, n->hostname);
			return;
		}

		inpkt = outpkt;
	}

	/* Add sequence number */

	seqno_t seqno = htonl(++(n->sent_seqno));
	memcpy(SEQNO(inpkt), &seqno, sizeof seqno);
	inpkt->len += sizeof seqno;

	/* Encrypt the packet */

	if(cipher_active(n->outcipher)) {
		outpkt = pkt[nextpkt++];
		outlen = MAXSIZE;

		if(!cipher_encrypt(n->outcipher, SEQNO(inpkt), inpkt->len, SEQNO(outpkt), &outlen, true)) {
			logger(DEBUG_TRAFFIC, LOG_ERR, "Error while encrypting packet to %s (%s)", n->name, n->hostname);
			goto end;
		}

		outpkt->len = outlen;
		inpkt = outpkt;
	}

	/* Add the message authentication code */

	if(digest_active(n->outdigest)) {
		if(!digest_create(n->outdigest, SEQNO(inpkt), inpkt->len, SEQNO(inpkt) + inpkt->len)) {
			logger(DEBUG_TRAFFIC, LOG_ERR, "Error while encrypting packet to %s (%s)", n->name, n->hostname);
			goto end;
		}

		inpkt->len += digest_length(n->outdigest);
	}

	/* Send the packet */

	const sockaddr_t *sa = NULL;
	int sock;

	if(n->status.send_locally)
		choose_local_address(n, &sa, &sock);
	if(!sa)
		choose_udp_address(n, &sa, &sock);

#if defined(SOL_IP) && defined(IP_TOS)
	if(priorityinheritance && origpriority != priority
	   && listen_socket[n->sock].sa.sa.sa_family == AF_INET) {
		priority = origpriority;
		logger(DEBUG_TRAFFIC, LOG_DEBUG, "Setting outgoing packet priority to %d", priority);
		if(setsockopt(listen_socket[n->sock].udp.fd, SOL_IP, IP_TOS, &priority, sizeof(priority))) /* SO_PRIORITY doesn't seem to work */
			logger(DEBUG_ALWAYS, LOG_ERR, "System call `%s' failed: %s", "setsockopt", sockstrerror(sockerrno));
	}
#endif

	if(sendto(listen_socket[sock].udp.fd, SEQNO(inpkt), inpkt->len, 0, &sa->sa, SALEN(sa->sa)) < 0 && !sockwouldblock(sockerrno)) {
		if(sockmsgsize(sockerrno)) {
			if(n->maxmtu >= origlen)
				n->maxmtu = origlen - 1;
			if(n->mtu >= origlen)
				n->mtu = origlen - 1;
			try_fix_mtu(n);
		} else
			logger(DEBUG_TRAFFIC, LOG_WARNING, "Error sending packet to %s (%s): %s", n->name, n->hostname, sockstrerror(sockerrno));
	}

end:
	origpkt->len = origlen;
#endif
}

bool send_sptps_data(node_t *to, node_t *from, int type, const void *data, size_t len) {
	node_t *relay = (to->via != myself && (type == PKT_PROBE || (len - SPTPS_DATAGRAM_OVERHEAD) <= to->via->minmtu)) ? to->via : to->nexthop;
	bool direct = from == myself && to == relay;
	bool relay_supported = (relay->options >> 24) >= 4;
	bool tcponly = (myself->options | relay->options) & OPTION_TCPONLY;

	/* Send it via TCP if it is a handshake packet, TCPOnly is in use, this is a relay packet that the other node cannot understand, or this packet is larger than the MTU. */

	if(type == SPTPS_HANDSHAKE || tcponly || (!direct && !relay_supported) || (type != PKT_PROBE && (len - SPTPS_DATAGRAM_OVERHEAD) > relay->minmtu)) {
		if((from != myself || to->status.validkey) && (to->nexthop->connection->options >> 24) >= 7) {
			char buf[len + sizeof to->id + sizeof from->id]; char* buf_ptr = buf;
			memcpy(buf_ptr, &to->id, sizeof to->id); buf_ptr += sizeof to->id;
			memcpy(buf_ptr, &from->id, sizeof from->id); buf_ptr += sizeof from->id;
			memcpy(buf_ptr, data, len); buf_ptr += len;
			logger(DEBUG_TRAFFIC, LOG_INFO, "Sending packet from %s (%s) to %s (%s) via %s (%s) (TCP)", from->name, from->hostname, to->name, to->hostname, to->nexthop->name, to->nexthop->hostname);
			return send_sptps_tcppacket(to->nexthop->connection, buf, sizeof buf);
		}

		char buf[len * 4 / 3 + 5];
		b64encode(data, buf, len);
		/* If no valid key is known yet, send the packets using ANS_KEY requests,
		   to ensure we get to learn the reflexive UDP address. */
		if(from == myself && !to->status.validkey) {
			to->incompression = myself->incompression;
			return send_request(to->nexthop->connection, "%d %s %s %s -1 -1 -1 %d", ANS_KEY, from->name, to->name, buf, to->incompression);
		} else {
			return send_request(to->nexthop->connection, "%d %s %s %d %s", REQ_KEY, from->name, to->name, SPTPS_PACKET, buf);
		}
	}

	size_t overhead = 0;
	if(relay_supported) overhead += sizeof to->id + sizeof from->id;
	char buf[len + overhead]; char* buf_ptr = buf;
	if(relay_supported) {
		if(direct) {
			/* Inform the recipient that this packet was sent directly. */
			node_id_t nullid = {};
			memcpy(buf_ptr, &nullid, sizeof nullid); buf_ptr += sizeof nullid;
		} else {
			memcpy(buf_ptr, &to->id, sizeof to->id); buf_ptr += sizeof to->id;
		}
		memcpy(buf_ptr, &from->id, sizeof from->id); buf_ptr += sizeof from->id;

	}
	/* TODO: if this copy turns out to be a performance concern, change sptps_send_record() to add some "pre-padding" to the buffer and use that instead */
	memcpy(buf_ptr, data, len); buf_ptr += len;

	const sockaddr_t *sa = NULL;
	int sock;
	if(relay->status.send_locally)
		choose_local_address(relay, &sa, &sock);
	if(!sa)
		choose_udp_address(relay, &sa, &sock);
	logger(DEBUG_TRAFFIC, LOG_INFO, "Sending packet from %s (%s) to %s (%s) via %s (%s) (UDP)", from->name, from->hostname, to->name, to->hostname, relay->name, relay->hostname);
	if(sendto(listen_socket[sock].udp.fd, buf, buf_ptr - buf, 0, &sa->sa, SALEN(sa->sa)) < 0 && !sockwouldblock(sockerrno)) {
		if(sockmsgsize(sockerrno)) {
			// Compensate for SPTPS overhead
			len -= SPTPS_DATAGRAM_OVERHEAD;
			if(relay->maxmtu >= len)
				relay->maxmtu = len - 1;
			if(relay->mtu >= len)
				relay->mtu = len - 1;
			try_fix_mtu(relay);
		} else {
			logger(DEBUG_TRAFFIC, LOG_WARNING, "Error sending UDP SPTPS packet to %s (%s): %s", relay->name, relay->hostname, sockstrerror(sockerrno));
			return false;
		}
	}

	return true;
}

bool receive_sptps_record(void *handle, uint8_t type, const void *data, uint16_t len) {
	node_t *from = handle;

	if(type == SPTPS_HANDSHAKE) {
		if(!from->status.validkey) {
			from->status.validkey = true;
			from->status.waitingforkey = false;
			logger(DEBUG_META, LOG_INFO, "SPTPS key exchange with %s (%s) succesful", from->name, from->hostname);
		}
		return true;
	}

	if(len > MTU) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Packet from %s (%s) larger than maximum supported size (%d > %d)", from->name, from->hostname, len, MTU);
		return false;
	}

	vpn_packet_t inpkt;
	inpkt.offset = DEFAULT_PACKET_OFFSET;

	if(type == PKT_PROBE) {
		if(!from->status.udppacket) {
			logger(DEBUG_ALWAYS, LOG_ERR, "Got SPTPS PROBE packet from %s (%s) via TCP", from->name, from->hostname);
			return false;
		}
		inpkt.len = len;
		memcpy(DATA(&inpkt), data, len);
		if(inpkt.len > from->maxrecentlen)
			from->maxrecentlen = inpkt.len;
		udp_probe_h(from, &inpkt, len);
		return true;
	}

	if(type & ~(PKT_COMPRESSED | PKT_MAC)) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Unexpected SPTPS record type %d len %d from %s (%s)", type, len, from->name, from->hostname);
		return false;
	}

	/* Check if we have the headers we need */
	if(routing_mode != RMODE_ROUTER && !(type & PKT_MAC)) {
		logger(DEBUG_TRAFFIC, LOG_ERR, "Received packet from %s (%s) without MAC header (maybe Mode is not set correctly)", from->name, from->hostname);
		return false;
	} else if(routing_mode == RMODE_ROUTER && (type & PKT_MAC)) {
		logger(DEBUG_TRAFFIC, LOG_WARNING, "Received packet from %s (%s) with MAC header (maybe Mode is not set correctly)", from->name, from->hostname);
	}

	int offset = (type & PKT_MAC) ? 0 : 14;
	if(type & PKT_COMPRESSED) {
		length_t ulen = uncompress_packet(DATA(&inpkt) + offset, (const uint8_t *)data, len, from->incompression);
		if(ulen < 0) {
			return false;
		} else {
			inpkt.len = ulen + offset;
		}
		if(inpkt.len > MAXSIZE)
			abort();
	} else {
		memcpy(DATA(&inpkt) + offset, data, len);
		inpkt.len = len + offset;
	}

	/* Generate the Ethernet packet type if necessary */
	if(offset) {
		switch(DATA(&inpkt)[14] >> 4) {
			case 4:
				DATA(&inpkt)[12] = 0x08;
				DATA(&inpkt)[13] = 0x00;
				break;
			case 6:
				DATA(&inpkt)[12] = 0x86;
				DATA(&inpkt)[13] = 0xDD;
				break;
			default:
				logger(DEBUG_TRAFFIC, LOG_ERR,
						   "Unknown IP version %d while reading packet from %s (%s)",
						   DATA(&inpkt)[14] >> 4, from->name, from->hostname);
				return false;
		}
	}

	if(from->status.udppacket && inpkt.len > from->maxrecentlen)
		from->maxrecentlen = inpkt.len;

	receive_packet(from, &inpkt);
	return true;
}

// This function tries to get SPTPS keys, if they aren't already known.
// This function makes no guarantees - it is up to the caller to check the node's state to figure out if the keys are available.
static void try_sptps(node_t *n) {
	if(n->status.validkey)
		return;

	logger(DEBUG_TRAFFIC, LOG_INFO, "No valid key known yet for %s (%s)", n->name, n->hostname);

	if(!n->status.waitingforkey)
		send_req_key(n);
	else if(n->last_req_key + 10 < now.tv_sec) {
		logger(DEBUG_ALWAYS, LOG_DEBUG, "No key from %s after 10 seconds, restarting SPTPS", n->name);
		sptps_stop(&n->sptps);
		n->status.waitingforkey = false;
		send_req_key(n);
	}

	return;
}

static void send_udp_probe_packet(node_t *n, int len) {
	vpn_packet_t packet;
	packet.offset = DEFAULT_PACKET_OFFSET;
	memset(DATA(&packet), 0, 14);
	randomize(DATA(&packet) + 14, len - 14);
	packet.len = len;
	packet.priority = 0;

	logger(DEBUG_TRAFFIC, LOG_INFO, "Sending UDP probe length %d to %s (%s)", len, n->name, n->hostname);

	send_udppacket(n, &packet);
}

// This function tries to establish a UDP tunnel to a node so that packets can be sent.
// If a tunnel is already established, it makes sure it stays up.
// This function makes no guarantees - it is up to the caller to check the node's state to figure out if UDP is usable.
static void try_udp(node_t* n) {
	if(!udp_discovery)
		return;

	/* Send gratuitous probe replies to 1.1 nodes. */

	if((n->options >> 24) >= 3 && n->status.udp_confirmed) {
		struct timeval ping_tx_elapsed;
		timersub(&now, &n->udp_reply_sent, &ping_tx_elapsed);

		if(ping_tx_elapsed.tv_sec >= udp_discovery_keepalive_interval - 1) {
			n->udp_reply_sent = now;
			if(n->maxrecentlen) {
				vpn_packet_t pkt;
				pkt.len = n->maxrecentlen;
				pkt.offset = DEFAULT_PACKET_OFFSET;
				memset(DATA(&pkt), 0, 14);
				randomize(DATA(&pkt) + 14, MIN_PROBE_SIZE - 14);
				send_udp_probe_reply(n, &pkt, pkt.len);
				n->maxrecentlen = 0;
			}
		}
	}

	/* Probe request */

	struct timeval ping_tx_elapsed;
	timersub(&now, &n->udp_ping_sent, &ping_tx_elapsed);

	int interval = n->status.udp_confirmed ? udp_discovery_keepalive_interval : udp_discovery_interval;

	if(ping_tx_elapsed.tv_sec >= interval) {
		send_udp_probe_packet(n, MIN_PROBE_SIZE);
		n->udp_ping_sent = now;

		if(localdiscovery && !n->status.udp_confirmed && n->prevedge) {
			n->status.send_locally = true;
			send_udp_probe_packet(n, MIN_PROBE_SIZE);
			n->status.send_locally = false;
		}
	}
}

static length_t choose_initial_maxmtu(node_t *n) {
#ifdef IP_MTU

	int sock = -1;

	const sockaddr_t *sa = NULL;
	int sockindex;
	choose_udp_address(n, &sa, &sockindex);
	if(!sa)
		return MTU;

	sock = socket(sa->sa.sa_family, SOCK_DGRAM, IPPROTO_UDP);
	if(sock < 0) {
		logger(DEBUG_TRAFFIC, LOG_ERR, "Creating MTU assessment socket for %s (%s) failed: %s", n->name, n->hostname, sockstrerror(sockerrno));
		return MTU;
	}

	if(connect(sock, &sa->sa, SALEN(sa->sa))) {
		logger(DEBUG_TRAFFIC, LOG_ERR, "Connecting MTU assessment socket for %s (%s) failed: %s", n->name, n->hostname, sockstrerror(sockerrno));
		close(sock);
		return MTU;
	}

	int ip_mtu;
	socklen_t ip_mtu_len = sizeof ip_mtu;
	if(getsockopt(sock, IPPROTO_IP, IP_MTU, &ip_mtu, &ip_mtu_len)) {
		logger(DEBUG_TRAFFIC, LOG_ERR, "getsockopt(IP_MTU) on %s (%s) failed: %s", n->name, n->hostname, sockstrerror(sockerrno));
		close(sock);
		return MTU;
	}

	close(sock);

	/* getsockopt(IP_MTU) returns the MTU of the physical interface.
	   We need to remove various overheads to get to the tinc MTU. */
	length_t mtu = ip_mtu;
	mtu -= (sa->sa.sa_family == AF_INET6) ? sizeof(struct ip6_hdr) : sizeof(struct ip);
	mtu -= 8; /* UDP */
	if(n->status.sptps) {
		mtu -= SPTPS_DATAGRAM_OVERHEAD;
		if((n->options >> 24) >= 4)
			mtu -= sizeof(node_id_t) + sizeof(node_id_t);
#ifndef DISABLE_LEGACY
	} else {
		mtu -= digest_length(n->outdigest);

		/* Now it's tricky. We use CBC mode, so the length of the
		   encrypted payload must be a multiple of the blocksize. The
		   sequence number is also part of the encrypted payload, so we
		   must account for it after correcting for the blocksize.
		   Furthermore, the padding in the last block must be at least
		   1 byte. */

		length_t blocksize = cipher_blocksize(n->outcipher);

		if(blocksize > 1) {
			mtu /= blocksize;
			mtu *= blocksize;
			mtu--;
		}

		mtu -= 4; // seqno
#endif
	}

	if (mtu < 512) {
		logger(DEBUG_TRAFFIC, LOG_ERR, "getsockopt(IP_MTU) on %s (%s) returned absurdly small value: %d", n->name, n->hostname, ip_mtu);
		return MTU;
	}
	if (mtu > MTU)
		return MTU;

	logger(DEBUG_TRAFFIC, LOG_INFO, "Using system-provided maximum tinc MTU for %s (%s): %hd", n->name, n->hostname, mtu);
	return mtu;

#else

	return MTU;

#endif
}

/* This function tries to determines the MTU of a node.
   By calling this function repeatedly, n->minmtu will be progressively
   increased, and at some point, n->mtu will be fixed to n->minmtu.  If the MTU
   is already fixed, this function checks if it can be increased.
*/

static void try_mtu(node_t *n) {
	if(!(n->options & OPTION_PMTU_DISCOVERY))
		return;

	if(udp_discovery && !n->status.udp_confirmed) {
		n->maxrecentlen = 0;
		n->mtuprobes = 0;
		n->minmtu = 0;
		n->maxmtu = MTU;
		return;
	}

	/* mtuprobes == 0..19: initial discovery, send bursts with 1 second interval, mtuprobes++
	   mtuprobes ==    20: fix MTU, and go to -1
	   mtuprobes ==    -1: send one maxmtu and one maxmtu+1 probe every pinginterval
	   mtuprobes ==-2..-3: send one maxmtu probe every second
	   mtuprobes ==    -4: maxmtu no longer valid, reset minmtu and maxmtu and go to 0 */

	struct timeval elapsed;
	timersub(&now, &n->mtu_ping_sent, &elapsed);
	if(n->mtuprobes >= 0) {
		if(n->mtuprobes != 0 && elapsed.tv_sec == 0 && elapsed.tv_usec < 333333)
			return;
	} else {
		if(n->mtuprobes < -1) {
			if(elapsed.tv_sec < 1)
				return;
		} else {
			if(elapsed.tv_sec < pinginterval)
				return;
		}
	}

	n->mtu_ping_sent = now;

	try_fix_mtu(n);

	if(n->mtuprobes < -3) {
		/* We lost three MTU probes, restart discovery */
		logger(DEBUG_TRAFFIC, LOG_INFO, "Decrease in PMTU to %s (%s) detected, restarting PMTU discovery", n->name, n->hostname);
		n->mtuprobes = 0;
		n->minmtu = 0;
	}

	if(n->mtuprobes < 0) {
		/* After the initial discovery, we only send one maxmtu and one
		   maxmtu+1 probe to detect PMTU increases. */
		send_udp_probe_packet(n, n->maxmtu);
		if(n->mtuprobes == -1 && n->maxmtu + 1 < MTU)
			send_udp_probe_packet(n, n->maxmtu + 1);
		n->mtuprobes--;
	} else {
		/* Before initial discovery begins, set maxmtu to the most likely value.
		   If it's underestimated, we will correct it after initial discovery. */
		if(n->mtuprobes == 0)
			n->maxmtu = choose_initial_maxmtu(n);

		for (;;) {
			/* Decreasing the number of probes per cycle might make the algorithm react faster to lost packets,
			   but it will typically increase convergence time in the no-loss case. */
			const length_t probes_per_cycle = 8;

			/* This magic value was determined using math simulations.
			   It will result in a 1329-byte first probe, followed (if there was a reply) by a 1407-byte probe.
			   Since 1407 is just below the range of tinc MTUs over typical networks,
			   this fine-tuning allows tinc to cover a lot of ground very quickly.
			   This fine-tuning is only valid for maxmtu = MTU; if maxmtu is smaller,
			   then it's better to use a multiplier of 1. Indeed, this leads to an interesting scenario
			   if choose_initial_maxmtu() returns the actual MTU value - it will get confirmed with one single probe. */
			const float multiplier = (n->maxmtu == MTU) ? 0.97 : 1;

			const float cycle_position = probes_per_cycle - (n->mtuprobes % probes_per_cycle) - 1;
			const length_t minmtu = MAX(n->minmtu, 512);
			const float interval = n->maxmtu - minmtu;

			/* The core of the discovery algorithm is this exponential.
			   It produces very large probes early in the cycle, and then it very quickly decreases the probe size.
			   This reflects the fact that in the most difficult cases, we don't get any feedback for probes that
			   are too large, and therefore we need to concentrate on small offsets so that we can quickly converge
			   on the precise MTU as we are approaching it.
			   The last probe of the cycle is always 1 byte in size - this is to make sure we'll get at least one
			   reply per cycle so that we can make progress. */
			const length_t offset = powf(interval, multiplier * cycle_position / (probes_per_cycle - 1));

			length_t maxmtu = n->maxmtu;
			send_udp_probe_packet(n, minmtu + offset);
			/* If maxmtu changed, it means the probe was rejected by the system because it was too large.
			   In that case, we recalculate with the new maxmtu and try again. */
			if(n->mtuprobes < 0 || maxmtu == n->maxmtu)
				break;
		}

		if(n->mtuprobes >= 0)
			n->mtuprobes++;
	}
}

/* These functions try to establish a tunnel to a node (or its relay) so that
   packets can be sent (e.g. exchange keys).
   If a tunnel is already established, it tries to improve it (e.g. by trying
   to establish a UDP tunnel instead of TCP).  This function makes no
   guarantees - it is up to the caller to check the node's state to figure out
   if TCP and/or UDP is usable.  By calling this function repeatedly, the
   tunnel is gradually improved until we hit the wall imposed by the underlying
   network environment.  It is recommended to call this function every time a
   packet is sent (or intended to be sent) to a node, so that the tunnel keeps
   improving as packets flow, and then gracefully downgrades itself as it goes
   idle.
*/

static void try_tx_sptps(node_t *n, bool mtu) {
	/* If n is a TCP-only neighbor, we'll only use "cleartext" PACKET
	   messages anyway, so there's no need for SPTPS at all. */

	if(n->connection && ((myself->options | n->options) & OPTION_TCPONLY))
		return;

	/* Otherwise, try to do SPTPS authentication with n if necessary. */

	try_sptps(n);

	/* Do we need to statically relay packets? */

	node_t *via = (n->via == myself) ? n->nexthop : n->via;

	/* If the static relay doesn't support SPTPS, everything goes via TCP anyway. */

	if((via->options >> 24) < 4)
		return;

	/* If we do have a static relay, try everything with that one instead. */

	if(via != n)
		return try_tx_sptps(via, mtu);

	/* Otherwise, try to establish UDP connectivity. */

	try_udp(n);
	if(mtu)
		try_mtu(n);

	/* If we don't have UDP connectivity (yet), we need to use a dynamic relay (nexthop)
	   while we try to establish direct connectivity. */

	if(!n->status.udp_confirmed && n != n->nexthop && (n->nexthop->options >> 24) >= 4)
		try_tx_sptps(n->nexthop, mtu);
}

static void try_tx_legacy(node_t *n, bool mtu) {
	/* Does he have our key? If not, send one. */

	if(!n->status.validkey_in)
		send_ans_key(n);

	/* Check if we already have a key, or request one. */

	if(!n->status.validkey) {
		if(n->last_req_key + 10 <= now.tv_sec) {
			send_req_key(n);
			n->last_req_key = now.tv_sec;
		}
		return;
	}

	try_udp(n);
	if(mtu)
		try_mtu(n);
}

void try_tx(node_t *n, bool mtu) {
	if(n->status.sptps)
		try_tx_sptps(n, mtu);
	else
		try_tx_legacy(n, mtu);
}

void send_packet(node_t *n, vpn_packet_t *packet) {
	// If it's for myself, write it to the tun/tap device.

	if(n == myself) {
		if(overwrite_mac)
			 memcpy(DATA(packet), mymac.x, ETH_ALEN);
		n->out_packets++;
		n->out_bytes += packet->len;
		devops.write(packet);
		return;
	}

	logger(DEBUG_TRAFFIC, LOG_ERR, "Sending packet of %d bytes to %s (%s)", packet->len, n->name, n->hostname);

	// If the node is not reachable, drop it.

	if(!n->status.reachable) {
		logger(DEBUG_TRAFFIC, LOG_INFO, "Node %s (%s) is not reachable", n->name, n->hostname);
		return;
	}

	// Keep track of packet statistics.

	n->out_packets++;
	n->out_bytes += packet->len;

	// Check if it should be sent as an SPTPS packet.

	if(n->status.sptps) {
		send_sptps_packet(n, packet);
		try_tx_sptps(n, true);
		return;
	}

	// Determine which node to actually send it to.

	node_t *via = (packet->priority == -1 || n->via == myself) ? n->nexthop : n->via;

	if(via != n)
		logger(DEBUG_TRAFFIC, LOG_INFO, "Sending packet to %s via %s (%s)", n->name, via->name, n->via->hostname);

	// Try to send via UDP, unless TCP is forced.

	if(packet->priority == -1 || ((myself->options | via->options) & OPTION_TCPONLY)) {
		if(!send_tcppacket(via->connection, packet))
			terminate_connection(via->connection, true);
		return;
	}

	send_udppacket(via, packet);
	try_tx_legacy(via, true);
}

void broadcast_packet(const node_t *from, vpn_packet_t *packet) {
	// Always give ourself a copy of the packet.
	if(from != myself)
		send_packet(myself, packet);

	// In TunnelServer mode, do not forward broadcast packets.
	// The MST might not be valid and create loops.
	if(tunnelserver || broadcast_mode == BMODE_NONE)
		return;

	logger(DEBUG_TRAFFIC, LOG_INFO, "Broadcasting packet of %d bytes from %s (%s)",
			   packet->len, from->name, from->hostname);

	switch(broadcast_mode) {
		// In MST mode, broadcast packets travel via the Minimum Spanning Tree.
		// This guarantees all nodes receive the broadcast packet, and
		// usually distributes the sending of broadcast packets over all nodes.
		case BMODE_MST:
			for list_each(connection_t, c, connection_list)
				if(c->edge && c->status.mst && c != from->nexthop->connection)
					send_packet(c->node, packet);
			break;

		// In direct mode, we send copies to each node we know of.
		// However, this only reaches nodes that can be reached in a single hop.
		// We don't have enough information to forward broadcast packets in this case.
		case BMODE_DIRECT:
			if(from != myself)
				break;

			for splay_each(node_t, n, node_tree)
				if(n->status.reachable && n != myself && ((n->via == myself && n->nexthop == n) || n->via == n))
					send_packet(n, packet);
			break;

		default:
			break;
	}
}

/* We got a packet from some IP address, but we don't know who sent it.  Try to
   verify the message authentication code against all active session keys.
   Since this is actually an expensive operation, we only do a full check once
   a minute, the rest of the time we only check against nodes for which we know
   an IP address that matches the one from the packet.  */

static node_t *try_harder(const sockaddr_t *from, const vpn_packet_t *pkt) {
	node_t *match = NULL;
	bool hard = false;
	static time_t last_hard_try = 0;

	for splay_each(node_t, n, node_tree) {
		if(!n->status.reachable || n == myself)
			continue;

		if((n->status.sptps && !n->sptps.instate) || !n->status.validkey_in)
			continue;

		bool soft = false;

		for splay_each(edge_t, e, n->edge_tree) {
			if(!e->reverse)
				continue;
			if(!sockaddrcmp_noport(from, &e->reverse->address)) {
				soft = true;
				break;
			}
		}

		if(!soft) {
			if(last_hard_try == now.tv_sec)
				continue;
			hard = true;
		}

		if(!try_mac(n, pkt))
			continue;

		match = n;
		break;
	}

	if(hard)
		last_hard_try = now.tv_sec;

	return match;
}

void handle_incoming_vpn_data(void *data, int flags) {
	listen_socket_t *ls = data;
	vpn_packet_t pkt;
	char *hostname;
	node_id_t nullid = {};
	sockaddr_t addr = {};
	socklen_t addrlen = sizeof addr;
	node_t *from, *to;
	bool direct = false;

	pkt.offset = 0;
	int len = recvfrom(ls->udp.fd, DATA(&pkt), MAXSIZE, 0, &addr.sa, &addrlen);

	if(len <= 0 || len > MAXSIZE) {
		if(!sockwouldblock(sockerrno))
			logger(DEBUG_ALWAYS, LOG_ERR, "Receiving packet failed: %s", sockstrerror(sockerrno));
		return;
	}

	pkt.len = len;

	sockaddrunmap(&addr); /* Some braindead IPv6 implementations do stupid things. */

	// Try to figure out who sent this packet.

	node_t *n = lookup_node_udp(&addr);

	if(n && !n->status.udp_confirmed)
		n = NULL; // Don't believe it if we don't have confirmation yet.

	if(!n) {
		// It might be from a 1.1 node, which might have a source ID in the packet.
		pkt.offset = 2 * sizeof(node_id_t);
		from = lookup_node_id(SRCID(&pkt));
		if(from && !memcmp(DSTID(&pkt), &nullid, sizeof nullid) && from->status.sptps) {
			if(sptps_verify_datagram(&from->sptps, DATA(&pkt), pkt.len - 2 * sizeof(node_id_t)))
				n = from;
			else
				goto skip_harder;
		}
	}

	if(!n) {
		pkt.offset = 0;
		n = try_harder(&addr, &pkt);
	}

skip_harder:
	if(!n) {
		if(debug_level >= DEBUG_PROTOCOL) {
			hostname = sockaddr2hostname(&addr);
			logger(DEBUG_PROTOCOL, LOG_WARNING, "Received UDP packet from unknown source %s", hostname);
			free(hostname);
		}
		return;
	}

	if(n->status.sptps) {
		pkt.offset = 2 * sizeof(node_id_t);

		if(!memcmp(DSTID(&pkt), &nullid, sizeof nullid)) {
			direct = true;
			from = n;
			to = myself;
		} else {
			from = lookup_node_id(SRCID(&pkt));
			to = lookup_node_id(DSTID(&pkt));
		}
		if(!from || !to) {
			logger(DEBUG_PROTOCOL, LOG_WARNING, "Received UDP packet from %s (%s) with unknown source and/or destination ID", n->name, n->hostname);
			return;
		}

		/* The packet is supposed to come from the originator or its static relay
		   (i.e. with no dynamic relays in between).
		   If it did not, "help" the static relay by sending it UDP info.
		   Note that we only do this if we're the destination or the static relay;
		   otherwise every hop would initiate its own UDP info message, resulting in elevated chatter. */

		if(n != from->via && to->via == myself)
			send_udp_info(myself, from);

		/* If we're not the final recipient, relay the packet. */

		if(to != myself) {
			send_sptps_data(to, from, 0, DATA(&pkt), pkt.len - 2 * sizeof(node_id_t));
			try_tx_sptps(to, true);
			return;
		}
	} else {
		direct = true;
		from = n;
	}

	pkt.offset = 0;
	if(!receive_udppacket(from, &pkt))
		return;

	n->sock = ls - listen_socket;
	if(direct && sockaddrcmp(&addr, &n->address))
		update_node_udp(n, &addr);

	/* If the packet went through a relay, help the sender find the appropriate MTU
	   through the relay path. */

	if(!direct)
		send_mtu_info(myself, n, MTU);
}

void handle_device_data(void *data, int flags) {
	vpn_packet_t packet;
	packet.offset = DEFAULT_PACKET_OFFSET;
	packet.priority = 0;

	if(devops.read(&packet)) {
		myself->in_packets++;
		myself->in_bytes += packet.len;
		route(myself, &packet);
	}
}
