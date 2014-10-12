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
#include "graph.h"
#include "logger.h"
#include "net.h"
#include "netutl.h"
#include "protocol.h"
#include "route.h"
#include "utils.h"
#include "xalloc.h"

int keylifetime = 0;
#ifdef HAVE_LZO
static char lzo_wrkmem[LZO1X_999_MEM_COMPRESS > LZO1X_1_MEM_COMPRESS ? LZO1X_999_MEM_COMPRESS : LZO1X_1_MEM_COMPRESS];
#endif

static void send_udppacket(node_t *, vpn_packet_t *);

unsigned replaywin = 16;
bool localdiscovery = true;

#define MAX_SEQNO 1073741824

/* mtuprobes == 1..30: initial discovery, send bursts with 1 second interval
   mtuprobes ==    31: sleep pinginterval seconds
   mtuprobes ==    32: send 1 burst, sleep pingtimeout second
   mtuprobes ==    33: no response from other side, restart PMTU discovery process

   Probes are sent in batches of at least three, with random sizes between the
   lower and upper boundaries for the MTU thus far discovered.

   After the initial discovery, a fourth packet is added to each batch with a
   size larger than the currently known PMTU, to test if the PMTU has increased.

   In case local discovery is enabled, another packet is added to each batch,
   which will be broadcast to the local network.

*/

static void send_mtu_probe_handler(void *data) {
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

	for(int i = 0; i < 4 + localdiscovery; i++) {
		int len;

		if(i == 0) {
			if(n->mtuprobes < 30 || n->maxmtu + 8 >= MTU)
				continue;
			len = n->maxmtu + 8;
		} else if(n->maxmtu <= n->minmtu) {
			len = n->maxmtu;
		} else {
			len = n->minmtu + 1 + rand() % (n->maxmtu - n->minmtu);
		}

		if(len < 64)
			len = 64;

		vpn_packet_t packet;
		packet.offset = DEFAULT_PACKET_OFFSET;
		memset(DATA(&packet), 0, 14);
		randomize(DATA(&packet) + 14, len - 14);
		packet.len = len;
		packet.priority = 0;
		n->status.send_locally = i >= 4 && n->mtuprobes <= 10 && n->prevedge;

		logger(DEBUG_TRAFFIC, LOG_INFO, "Sending MTU probe length %d to %s (%s)", len, n->name, n->hostname);

		send_udppacket(n, &packet);
	}

	n->status.send_locally = false;
	n->probe_counter = 0;
	gettimeofday(&n->probe_time, NULL);

	/* Calculate the packet loss of incoming traffic by comparing the rate of
	   packets received to the rate with which the sequence number has increased.
	 */

	if(n->received > n->prev_received)
		n->packetloss = 1.0 - (n->received - n->prev_received) / (float)(n->received_seqno - n->prev_received_seqno);
	else
		n->packetloss = n->received_seqno <= n->prev_received_seqno;

	n->prev_received_seqno = n->received_seqno;
	n->prev_received = n->received;

end:
	timeout_set(&n->mtutimeout, &(struct timeval){timeout, rand() % 100000});
}

void send_mtu_probe(node_t *n) {
	timeout_add(&n->mtutimeout, send_mtu_probe_handler, n, &(struct timeval){1, 0});
	send_mtu_probe_handler(n);
}

static void mtu_probe_h(node_t *n, vpn_packet_t *packet, length_t len) {
	if(!DATA(packet)[0]) {
		logger(DEBUG_TRAFFIC, LOG_INFO, "Got MTU probe request %d from %s (%s)", packet->len, n->name, n->hostname);

		/* It's a probe request, send back a reply */

		/* Type 2 probe replies were introduced in protocol 17.3 */
		if ((n->options >> 24) >= 3) {
			uint8_t *data = DATA(packet);
			*data++ = 2;
			uint16_t len16 = htons(len); memcpy(data, &len16, 2); data += 2;
			struct timeval now;
			gettimeofday(&now, NULL);
			uint32_t sec = htonl(now.tv_sec); memcpy(data, &sec, 4); data += 4;
			uint32_t usec = htonl(now.tv_usec); memcpy(data, &usec, 4); data += 4;
			packet->len -= 10;
		} else {
			/* Legacy protocol: n won't understand type 2 probe replies. */
			DATA(packet)[0] = 1;
		}

		/* Temporarily set udp_confirmed, so that the reply is sent
		   back exactly the way it came in. */

		bool udp_confirmed = n->status.udp_confirmed;
		n->status.udp_confirmed = true;
		send_udppacket(n, packet);
		n->status.udp_confirmed = udp_confirmed;
	} else {
		length_t probelen = len;
		if (DATA(packet)[0] == 2) {
			if (len < 3)
				logger(DEBUG_TRAFFIC, LOG_WARNING, "Received invalid (too short) MTU probe reply from %s (%s)", n->name, n->hostname);
			else {
				uint16_t probelen16; memcpy(&probelen16, DATA(packet) + 1, 2); probelen = ntohs(probelen16);
			}
		}
		logger(DEBUG_TRAFFIC, LOG_INFO, "Got type %d MTU probe reply %d from %s (%s)", DATA(packet)[0], probelen, n->name, n->hostname);

		/* It's a valid reply: now we know bidirectional communication
		   is possible using the address and socket that the reply
		   packet used. */

		n->status.udp_confirmed = true;

		/* If we haven't established the PMTU yet, restart the discovery process. */

		if(n->mtuprobes > 30) {
			if (probelen == n->maxmtu + 8) {
				logger(DEBUG_TRAFFIC, LOG_INFO, "Increase in PMTU to %s (%s) detected, restarting PMTU discovery", n->name, n->hostname);
				n->maxmtu = MTU;
				n->mtuprobes = 10;
				return;
			}

			if(n->minmtu)
				n->mtuprobes = 30;
			else
				n->mtuprobes = 1;
		}

		/* If applicable, raise the minimum supported MTU */

		if(probelen > n->maxmtu)
			probelen = n->maxmtu;
		if(n->minmtu < probelen)
			n->minmtu = probelen;

		/* Calculate RTT and bandwidth.
		   The RTT is the time between the MTU probe burst was sent and the first
		   reply is received. The bandwidth is measured using the time between the
		   arrival of the first and third probe reply (or type 2 probe requests).
		 */

		struct timeval now, diff;
		gettimeofday(&now, NULL);
		timersub(&now, &n->probe_time, &diff);

		struct timeval probe_timestamp = now;
		if (DATA(packet)[0] == 2 && packet->len >= 11) {
			uint32_t sec; memcpy(&sec, DATA(packet) + 3, 4);
			uint32_t usec; memcpy(&usec, DATA(packet) + 7, 4);
			probe_timestamp.tv_sec = ntohl(sec);
			probe_timestamp.tv_usec = ntohl(usec);
		}
		
		n->probe_counter++;

		if(n->probe_counter == 1) {
			n->rtt = diff.tv_sec + diff.tv_usec * 1e-6;
			n->probe_time = probe_timestamp;
		} else if(n->probe_counter == 3) {
			struct timeval probe_timestamp_diff;
			timersub(&probe_timestamp, &n->probe_time, &probe_timestamp_diff);
			n->bandwidth = 2.0 * probelen / (probe_timestamp_diff.tv_sec + probe_timestamp_diff.tv_usec * 1e-6);
			logger(DEBUG_TRAFFIC, LOG_DEBUG, "%s (%s) RTT %.2f ms, burst bandwidth %.3f Mbit/s, rx packet loss %.2f %%", n->name, n->hostname, n->rtt * 1e3, n->bandwidth * 8e-6, n->packetloss * 1e2);
		}
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

	if(!digest_active(n->indigest) || inpkt->len < sizeof(seqno_t) + digest_length(n->indigest))
		return false;

	return digest_verify(n->indigest, SEQNO(inpkt), inpkt->len - digest_length(n->indigest), DATA(inpkt) + inpkt->len - digest_length(n->indigest));
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
		if(!sptps_receive_data(&n->sptps, DATA(inpkt), inpkt->len - 2 * sizeof(node_id_t))) {
			logger(DEBUG_TRAFFIC, LOG_ERR, "Got bad packet from %s (%s)", n->name, n->hostname);
			return false;
		}
		return true;
	}

	if(!n->status.validkey) {
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

	inpkt->priority = 0;

	if(!DATA(inpkt)[12] && !DATA(inpkt)[13])
		mtu_probe_h(n, inpkt, origlen);
	else
		receive_packet(n, inpkt);
	return true;
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

static bool try_sptps(node_t *n) {
	if(n->status.validkey)
		return true;

	/* If n is a TCP-only neighbor, we'll only use "cleartext" PACKET
	   messages anyway, so there's no need for SPTPS at all. */
	if(n->connection && ((myself->options | n->options) & OPTION_TCPONLY))
		return false;

	logger(DEBUG_TRAFFIC, LOG_INFO, "No valid key known yet for %s (%s)", n->name, n->hostname);

	if(!n->status.waitingforkey)
		send_req_key(n);
	else if(n->last_req_key + 10 < now.tv_sec) {
		logger(DEBUG_ALWAYS, LOG_DEBUG, "No key from %s after 10 seconds, restarting SPTPS", n->name);
		sptps_stop(&n->sptps);
		n->status.waitingforkey = false;
		send_req_key(n);
	}

	return false;
}

static void send_sptps_packet(node_t *n, vpn_packet_t *origpkt) {
	/* Note: condition order is as intended - even if we have a direct
	   metaconnection, we want to try SPTPS anyway as it's the only way to
	   get UDP going */
	if(!try_sptps(n) && !n->connection)
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

	/* Make sure we have a valid key */

	if(!n->status.validkey) {
		logger(DEBUG_TRAFFIC, LOG_INFO,
				   "No valid key known yet for %s (%s), forwarding via TCP",
				   n->name, n->hostname);

		if(n->last_req_key + 10 <= now.tv_sec) {
			send_req_key(n);
			n->last_req_key = now.tv_sec;
		}

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
		} else
			logger(DEBUG_TRAFFIC, LOG_WARNING, "Error sending packet to %s (%s): %s", n->name, n->hostname, sockstrerror(sockerrno));
	}

end:
	origpkt->len = origlen;
}

static bool send_sptps_data_priv(node_t *to, node_t *from, int type, const void *data, size_t len) {
	node_t *relay = (to->via != myself && (type == PKT_PROBE || (len - SPTPS_DATAGRAM_OVERHEAD) <= to->via->minmtu)) ? to->via : to->nexthop;
	bool direct = from == myself && to == relay;
	bool relay_supported = (relay->options >> 24) >= 4;
	bool tcponly = (myself->options | relay->options) & OPTION_TCPONLY;

	/* We don't really need the relay's key, but we need to establish a UDP tunnel with it and discover its MTU. */
	if (!direct && relay_supported && !tcponly)
		try_sptps(relay);

	/* Send it via TCP if it is a handshake packet, TCPOnly is in use, this is a relay packet that the other node cannot understand, or this packet is larger than the MTU.
	   TODO: When relaying, the original sender does not know the end-to-end PMTU (it only knows the PMTU of the first hop).
	         This can lead to scenarios where large packets are sent over UDP to relay, but then relay has no choice but fall back to TCP. */

	if(type == SPTPS_HANDSHAKE || tcponly || (!direct && !relay_supported) || (type != PKT_PROBE && (len - SPTPS_DATAGRAM_OVERHEAD) > relay->minmtu)) {
		char buf[len * 4 / 3 + 5];
		b64encode(data, buf, len);
		/* If no valid key is known yet, send the packets using ANS_KEY requests,
		   to ensure we get to learn the reflexive UDP address. */
		if(from == myself && !to->status.validkey) {
			to->incompression = myself->incompression;
			return send_request(to->nexthop->connection, "%d %s %s %s -1 -1 -1 %d", ANS_KEY, from->name, to->name, buf, to->incompression);
		} else {
			return send_request(to->nexthop->connection, "%d %s %s %d %s", REQ_KEY, from->name, to->name, REQ_SPTPS, buf);
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
	logger(DEBUG_TRAFFIC, LOG_INFO, "Sending packet from %s (%s) to %s (%s) via %s (%s)", from->name, from->hostname, to->name, to->hostname, relay->name, relay->hostname);
	if(sendto(listen_socket[sock].udp.fd, buf, buf_ptr - buf, 0, &sa->sa, SALEN(sa->sa)) < 0 && !sockwouldblock(sockerrno)) {
		if(sockmsgsize(sockerrno)) {
			// Compensate for SPTPS overhead
			len -= SPTPS_DATAGRAM_OVERHEAD;
			if(relay->maxmtu >= len)
				relay->maxmtu = len - 1;
			if(relay->mtu >= len)
				relay->mtu = len - 1;
		} else {
			logger(DEBUG_TRAFFIC, LOG_WARNING, "Error sending UDP SPTPS packet to %s (%s): %s", relay->name, relay->hostname, sockstrerror(sockerrno));
			return false;
		}
	}

	return true;
}

bool send_sptps_data(void *handle, uint8_t type, const void *data, size_t len) {
	return send_sptps_data_priv(handle, myself, type, data, len);
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
		inpkt.len = len;
		memcpy(DATA(&inpkt), data, len);
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
			 memcpy(DATA(packet), mymac.x, ETH_ALEN);
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

static node_t *try_harder(const sockaddr_t *from, const vpn_packet_t *pkt) {
	node_t *n = NULL;
	bool hard = false;
	static time_t last_hard_try = 0;

	for splay_each(edge_t, e, edge_weight_tree) {
		if(!e->to->status.reachable || e->to == myself)
			continue;

		if(sockaddrcmp_noport(from, &e->address)) {
			if(last_hard_try == now.tv_sec)
				continue;
			hard = true;
		}

		if(!try_mac(e->to, pkt))
			continue;

		n = e->to;
		break;
	}

	if(hard)
		last_hard_try = now.tv_sec;

	last_hard_try = now.tv_sec;
	return n;
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

		if(to != myself) {
			send_sptps_data_priv(to, n, 0, DATA(&pkt), pkt.len - 2 * sizeof(node_id_t));
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
