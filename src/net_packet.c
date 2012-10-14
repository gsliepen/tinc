/*
    net_packet.c -- Handles in- and outgoing VPN packets
    Copyright (C) 1998-2005 Ivo Timmermans,
                  2000-2012 Guus Sliepen <guus@tinc-vpn.org>
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
bool localdiscovery = false;

#define MAX_SEQNO 1073741824

/* mtuprobes == 1..30: initial discovery, send bursts with 1 second interval
   mtuprobes ==    31: sleep pinginterval seconds
   mtuprobes ==    32: send 1 burst, sleep pingtimeout second
   mtuprobes ==    33: no response from other side, restart PMTU discovery process

   Probes are sent in batches of three, with random sizes between the lower and
   upper boundaries for the MTU thus far discovered.

   In case local discovery is enabled, a fourth packet is added to each batch,
   which will be broadcast to the local network.
*/

static void send_mtu_probe_handler(int fd, short events, void *data) {
	node_t *n = data;
	int timeout = 1;

	n->mtuprobes++;

	if(!n->status.reachable || !n->status.validkey) {
		logger(DEBUG_TRAFFIC, LOG_INFO, "Trying to send MTU probe to unreachable or rekeying node %s (%s)", n->name, n->hostname);
		n->mtuprobes = 0;
		return;
	}

	if(n->mtuprobes > 32) {
		if(!n->minmtu) {
			n->mtuprobes = 31;
			timeout = pinginterval;
			goto end;
		}

		logger(DEBUG_TRAFFIC, LOG_INFO, "%s (%s) did not respond to UDP ping, restarting PMTU discovery", n->name, n->hostname);
		n->status.udp_confirmed = false;
		n->mtuprobes = 1;
		n->minmtu = 0;
		n->maxmtu = MTU;
	}

	if(n->mtuprobes >= 10 && n->mtuprobes < 32 && !n->minmtu) {
		logger(DEBUG_TRAFFIC, LOG_INFO, "No response to MTU probes from %s (%s)", n->name, n->hostname);
		n->mtuprobes = 31;
	}

	if(n->mtuprobes == 30 || (n->mtuprobes < 30 && n->minmtu >= n->maxmtu)) {
		if(n->minmtu > n->maxmtu)
			n->minmtu = n->maxmtu;
		else
			n->maxmtu = n->minmtu;
		n->mtu = n->minmtu;
		logger(DEBUG_TRAFFIC, LOG_INFO, "Fixing MTU of %s (%s) to %d after %d probes", n->name, n->hostname, n->mtu, n->mtuprobes);
		n->mtuprobes = 31;
	}

	if(n->mtuprobes == 31) {
		timeout = pinginterval;
		goto end;
	} else if(n->mtuprobes == 32) {
		timeout = pingtimeout;
	}

	for(int i = 0; i < 3 + localdiscovery; i++) {
		int len;

		if(n->maxmtu <= n->minmtu)
			len = n->maxmtu;
		else
			len = n->minmtu + 1 + rand() % (n->maxmtu - n->minmtu);

		if(len < 64)
			len = 64;

		vpn_packet_t packet;
		memset(packet.data, 0, 14);
		randomize(packet.data + 14, len - 14);
		packet.len = len;
		if(i >= 3 && n->mtuprobes <= 10)
			packet.priority = -1;
		else
			packet.priority = 0;

		logger(DEBUG_TRAFFIC, LOG_INFO, "Sending MTU probe length %d to %s (%s)", len, n->name, n->hostname);

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
	logger(DEBUG_TRAFFIC, LOG_INFO, "Got MTU probe length %d from %s (%s)", packet->len, n->name, n->hostname);

	if(!packet->data[0]) {
		packet->data[0] = 1;
		send_udppacket(n, packet);
	} else {
		n->status.udp_confirmed = true;

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
	logger(DEBUG_TRAFFIC, LOG_DEBUG, "Received packet of %d bytes from %s (%s)",
			   packet->len, n->name, n->hostname);

	n->in_packets++;
	n->in_bytes += packet->len;

	route(n, packet);
}

static bool try_mac(node_t *n, const vpn_packet_t *inpkt) {
	if(n->status.sptps)
		return sptps_verify_datagram(&n->sptps, (char *)&inpkt->seqno, inpkt->len);

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

	if(n->status.sptps) {
		sptps_receive_data(&n->sptps, (char *)&inpkt->seqno, inpkt->len);
		return;
	}

	if(!cipher_active(&n->incipher)) {
		logger(DEBUG_TRAFFIC, LOG_DEBUG, "Got packet from %s (%s) but he hasn't got our key yet",
					n->name, n->hostname);
		return;
	}

	/* Check packet length */

	if(inpkt->len < sizeof inpkt->seqno + digest_length(&n->indigest)) {
		logger(DEBUG_TRAFFIC, LOG_DEBUG, "Got too short packet from %s (%s)",
					n->name, n->hostname);
		return;
	}

	/* Check the message authentication code */

	if(digest_active(&n->indigest)) {
		inpkt->len -= n->indigest.maclength;
		if(!digest_verify(&n->indigest, &inpkt->seqno, inpkt->len, (const char *)&inpkt->seqno + inpkt->len)) {
			logger(DEBUG_TRAFFIC, LOG_DEBUG, "Got unauthenticated packet from %s (%s)", n->name, n->hostname);
			return;
		}
	}
	/* Decrypt the packet */

	if(cipher_active(&n->incipher)) {
		outpkt = pkt[nextpkt++];
		outlen = MAXSIZE;

		if(!cipher_decrypt(&n->incipher, &inpkt->seqno, inpkt->len, &outpkt->seqno, &outlen, true)) {
			logger(DEBUG_TRAFFIC, LOG_DEBUG, "Error decrypting packet from %s (%s)", n->name, n->hostname);
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
					logger(DEBUG_ALWAYS, LOG_WARNING, "Packet from %s (%s) is %d seqs in the future, dropped (%u)",
						n->name, n->hostname, inpkt->seqno - n->received_seqno - 1, n->farfuture);
					return;
				}
				logger(DEBUG_ALWAYS, LOG_WARNING, "Lost %d packets from %s (%s)",
						inpkt->seqno - n->received_seqno - 1, n->name, n->hostname);
				memset(n->late, 0, replaywin);
			} else if (inpkt->seqno <= n->received_seqno) {
				if((n->received_seqno >= replaywin * 8 && inpkt->seqno <= n->received_seqno - replaywin * 8) || !(n->late[(inpkt->seqno / 8) % replaywin] & (1 << inpkt->seqno % 8))) {
					logger(DEBUG_ALWAYS, LOG_WARNING, "Got late or replayed packet from %s (%s), seqno %d, last received %d",
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
			logger(DEBUG_TRAFFIC, LOG_ERR, "Error while uncompressing packet from %s (%s)",
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

static void send_sptps_packet(node_t *n, vpn_packet_t *origpkt) {
	if(!n->status.validkey) {
		logger(DEBUG_TRAFFIC, LOG_INFO, "No valid key known yet for %s (%s)", n->name, n->hostname);
		if(!n->status.waitingforkey)
			send_req_key(n);
		else if(n->last_req_key + 10 < time(NULL)) {
			logger(DEBUG_ALWAYS, LOG_DEBUG, "No key from %s after 10 seconds, restarting SPTPS", n->name);
			sptps_stop(&n->sptps);
			n->status.waitingforkey = false;
			send_req_key(n);
		}
		return;
	}

	uint8_t type = 0;
	int offset = 0;

	if(!(origpkt->data[12] | origpkt->data[13])) {
		sptps_send_record(&n->sptps, PKT_PROBE, (char *)origpkt->data, origpkt->len);
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
		int len = compress_packet(outpkt.data + offset, origpkt->data + offset, origpkt->len - offset, n->outcompression);
		if(len < 0) {
			logger(DEBUG_TRAFFIC, LOG_ERR, "Error while compressing packet to %s (%s)", n->name, n->hostname);
		} else if(len < origpkt->len - offset) {
			outpkt.len = len + offset;
			origpkt = &outpkt;
			type |= PKT_COMPRESSED;
		}
	}

	sptps_send_record(&n->sptps, type, (char *)origpkt->data + offset, origpkt->len - offset);
	return;
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
#endif
	int origpriority = origpkt->priority;

	if(!n->status.reachable) {
		logger(DEBUG_TRAFFIC, LOG_INFO, "Trying to send UDP packet to unreachable node %s (%s)", n->name, n->hostname);
		return;
	}

	if(n->status.sptps)
		return send_sptps_packet(n, origpkt);

	/* Make sure we have a valid key */

	if(!n->status.validkey) {
		time_t now = time(NULL);

		logger(DEBUG_TRAFFIC, LOG_INFO,
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

		if((outpkt->len = compress_packet(outpkt->data, inpkt->data, inpkt->len, n->outcompression)) < 0) {
			logger(DEBUG_TRAFFIC, LOG_ERR, "Error while compressing packet to %s (%s)",
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
			logger(DEBUG_TRAFFIC, LOG_ERR, "Error while encrypting packet to %s (%s)", n->name, n->hostname);
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

	/* Send the packet */

	sockaddr_t *sa;
	int sock;

	/* Overloaded use of priority field: -1 means local broadcast */

	if(origpriority == -1 && n->prevedge) {
		sockaddr_t broadcast;
		broadcast.in.sin_family = AF_INET;
		broadcast.in.sin_addr.s_addr = -1;
		broadcast.in.sin_port = n->prevedge->address.in.sin_port;
		sa = &broadcast;
		sock = 0;
	} else {
		if(origpriority == -1)
			origpriority = 0;

		if(n->status.udp_confirmed) {
			/* Address of this node is confirmed, so use it. */
			sa = &n->address;
			sock = n->sock;
		} else {
			/* Otherwise, go through the list of known addresses of
			   this node. The first address we try is always the
			   one in n->address; that could be set to the node's
			   reflexive UDP address discovered during key
			   exchange. The other known addresses are those found
			   in edges to this node. */

			static unsigned int i;
			int j = 0;
			edge_t *candidate = NULL;

			if(i) {
				for splay_each(edge_t, e, edge_weight_tree) {
					if(e->to != n)
						continue;
					j++;
					if(!candidate || j == i)
						candidate = e;
				}
			}

			if(!candidate) {
				sa = &n->address;
				sock = n->sock;
			} else {
				sa = &candidate->address;
				sock = rand() % listen_sockets;
			}

			if(i++)
				if(i > j)
					i = 0;
		}
	}

	/* Determine which socket we have to use */

	if(sa->sa.sa_family != listen_socket[sock].sa.sa.sa_family)
		for(sock = 0; sock < listen_sockets; sock++)
			if(sa->sa.sa_family == listen_socket[sock].sa.sa.sa_family)
				break;

	if(sock >= listen_sockets)
		sock = 0;

	if(!n->status.udp_confirmed)
		n->sock = sock;

#if defined(SOL_IP) && defined(IP_TOS)
	if(priorityinheritance && origpriority != priority
	   && listen_socket[n->sock].sa.sa.sa_family == AF_INET) {
		priority = origpriority;
		logger(DEBUG_TRAFFIC, LOG_DEBUG, "Setting outgoing packet priority to %d", priority);
		if(setsockopt(listen_socket[n->sock].udp, SOL_IP, IP_TOS, &priority, sizeof(priority))) /* SO_PRIORITY doesn't seem to work */
			logger(DEBUG_ALWAYS, LOG_ERR, "System call `%s' failed: %s", "setsockopt", strerror(errno));
	}
#endif

	socklen_t sl = SALEN(n->address.sa);

	if(sendto(listen_socket[sock].udp, (char *) &inpkt->seqno, inpkt->len, 0, &sa->sa, sl) < 0 && !sockwouldblock(sockerrno)) {
		if(sockmsgsize(sockerrno)) {
			if(n->maxmtu >= origlen)
				n->maxmtu = origlen - 1;
			if(n->mtu >= origlen)
				n->mtu = origlen - 1;
		} else
			logger(DEBUG_TRAFFIC, LOG_WARNING, "Error sending packet to %s (%s): %s", n->name, n->hostname, sockstrerror(sockerrno));
	}

end:
	origpkt->len = origlen;
}

bool send_sptps_data(void *handle, uint8_t type, const char *data, size_t len) {
	node_t *to = handle;

	/* Send it via TCP if it is a handshake packet, TCPOnly is in use, or this packet is larger than the MTU. */

	if(type >= SPTPS_HANDSHAKE || ((myself->options | to->options) & OPTION_TCPONLY) || (type != PKT_PROBE && len > to->minmtu)) {
		char buf[len * 4 / 3 + 5];
		b64encode(data, buf, len);
		/* If no valid key is known yet, send the packets using ANS_KEY requests,
		   to ensure we get to learn the reflexive UDP address. */
		if(!to->status.validkey)
			return send_request(to->nexthop->connection, "%d %s %s %s -1 -1 -1 %d", ANS_KEY, myself->name, to->name, buf, myself->incompression);
		else
			return send_request(to->nexthop->connection, "%d %s %s %d %s", REQ_KEY, myself->name, to->name, REQ_SPTPS, buf);
	}

	/* Otherwise, send the packet via UDP */

	struct sockaddr *sa;
	socklen_t sl;
	int sock;

	sa = &(to->address.sa);
	sl = SALEN(to->address.sa);
	sock = to->sock;

	if(sendto(listen_socket[sock].udp, data, len, 0, sa, sl) < 0 && !sockwouldblock(sockerrno)) {
		if(sockmsgsize(sockerrno)) {
			if(to->maxmtu >= len)
				to->maxmtu = len - 1;
			if(to->mtu >= len)
				to->mtu = len - 1;
		} else {
			logger(DEBUG_TRAFFIC, LOG_WARNING, "Error sending UDP SPTPS packet to %s (%s): %s", to->name, to->hostname, sockstrerror(sockerrno));
			return false;
		}
	}

	return true;
}

bool receive_sptps_record(void *handle, uint8_t type, const char *data, uint16_t len) {
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

	if(type == PKT_PROBE) {
		inpkt.len = len;
		memcpy(inpkt.data, data, len);
		mtu_probe_h(from, &inpkt, len);
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
		len = uncompress_packet(inpkt.data + offset, (const uint8_t *)data, len, from->incompression);
		if(len < 0) {
			return false;
		} else {
			inpkt.len = len + offset;
		}
		if(inpkt.len > MAXSIZE)
			abort();
	} else {
		memcpy(inpkt.data + offset, data, len);
		inpkt.len = len + offset;
	}

	/* Generate the Ethernet packet type if necessary */
	if(offset) {
		switch(inpkt.data[14] >> 4) {
			case 4:
				inpkt.data[12] = 0x08;
				inpkt.data[13] = 0x00;
				break;
			case 6:
				inpkt.data[12] = 0x86;
				inpkt.data[13] = 0xDD;
				break;
			default:
				logger(DEBUG_TRAFFIC, LOG_ERR,
						   "Unknown IP version %d while reading packet from %s (%s)",
						   inpkt.data[14] >> 4, from->name, from->hostname);
				return false;
		}
	}

	receive_packet(from, &inpkt);
	return true;
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
		devops.write(packet);
		return;
	}

	logger(DEBUG_TRAFFIC, LOG_ERR, "Sending packet of %d bytes to %s (%s)",
			   packet->len, n->name, n->hostname);

	if(!n->status.reachable) {
		logger(DEBUG_TRAFFIC, LOG_INFO, "Node %s (%s) is not reachable",
				   n->name, n->hostname);
		return;
	}

	n->out_packets++;
	n->out_bytes += packet->len;

	if(n->status.sptps) {
		send_sptps_packet(n, packet);
		return;
	}

	via = (packet->priority == -1 || n->via == myself) ? n->nexthop : n->via;

	if(via != n)
		logger(DEBUG_TRAFFIC, LOG_INFO, "Sending packet to %s via %s (%s)",
			   n->name, via->name, n->via->hostname);

	if(packet->priority == -1 || ((myself->options | via->options) & OPTION_TCPONLY)) {
		if(!send_tcppacket(via->connection, packet))
			terminate_connection(via->connection, true);
	} else
		send_udppacket(via, packet);
}

/* Broadcast a packet using the minimum spanning tree */

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
				if(c->status.active && c->status.mst && c != from->nexthop->connection)
					send_packet(c->node, packet);
			break;

		// In direct mode, we send copies to each node we know of.
		// However, this only reaches nodes that can be reached in a single hop.
		// We don't have enough information to forward broadcast packets in this case.
		case BMODE_DIRECT:
			if(from != myself)
				break;

			for splay_each(node_t, n, node_tree)
				if(n->status.reachable && ((n->via == myself && n->nexthop == n) || n->via == n))
					send_packet(n, packet);
			break;

		default:
			break;
	}
}

static node_t *try_harder(const sockaddr_t *from, const vpn_packet_t *pkt) {
	node_t *n = NULL;
	bool hard = false;
	static time_t last_hard_try = 0;
	time_t now = time(NULL);

	for splay_each(edge_t, e, edge_weight_tree) {
		if(!e->to->status.reachable || e->to == myself)
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

	last_hard_try = now;
	return n;
}

void handle_incoming_vpn_data(int sock, short events, void *data) {
	vpn_packet_t pkt;
	char *hostname;
	sockaddr_t from = {{0}};
	socklen_t fromlen = sizeof from;
	node_t *n;
	int len;

	len = recvfrom(sock, (char *) &pkt.seqno, MAXSIZE, 0, &from.sa, &fromlen);

	if(len <= 0 || len > MAXSIZE) {
		if(!sockwouldblock(sockerrno))
			logger(DEBUG_ALWAYS, LOG_ERR, "Receiving packet failed: %s", sockstrerror(sockerrno));
		return;
	}

	pkt.len = len;

	sockaddrunmap(&from); /* Some braindead IPv6 implementations do stupid things. */

	n = lookup_node_udp(&from);

	if(!n) {
		n = try_harder(&from, &pkt);
		if(n)
			update_node_udp(n, &from);
		else if(debug_level >= DEBUG_PROTOCOL) {
			hostname = sockaddr2hostname(&from);
			logger(DEBUG_PROTOCOL, LOG_WARNING, "Received UDP packet from unknown source %s", hostname);
			free(hostname);
			return;
		}
		else
			return;
	}

	n->sock = (intptr_t)data;

	receive_udppacket(n, &pkt);
}

void handle_device_data(int sock, short events, void *data) {
	vpn_packet_t packet;

	packet.priority = 0;

	if(devops.read(&packet)) {
		myself->in_packets++;
		myself->in_bytes += packet.len;
		route(myself, &packet);
	}
}
