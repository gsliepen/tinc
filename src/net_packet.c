/*
    net_packet.c -- Handles in- and outgoing VPN packets
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

    $Id: net_packet.c,v 1.1.2.43 2003/10/11 12:16:12 guus Exp $
*/

#include "system.h"

#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/hmac.h>

#include <zlib.h>
#include <lzo1x.h>

#include "avl_tree.h"
#include "conf.h"
#include "connection.h"
#include "device.h"
#include "event.h"
#include "graph.h"
#include "list.h"
#include "logger.h"
#include "net.h"
#include "netutl.h"
#include "protocol.h"
#include "process.h"
#include "route.h"
#include "utils.h"
#include "xalloc.h"

int keylifetime = 0;
int keyexpires = 0;
EVP_CIPHER_CTX packet_ctx;
static char lzo_wrkmem[LZO1X_999_MEM_COMPRESS > LZO1X_1_MEM_COMPRESS ? LZO1X_999_MEM_COMPRESS : LZO1X_1_MEM_COMPRESS];


#define MAX_SEQNO 1073741824

static length_t compress_packet(uint8_t *dest, const uint8_t *source, length_t len, int level)
{
	if(level == 10) {
		lzo_uint lzolen = MAXSIZE;
		lzo1x_1_compress(source, len, dest, &lzolen, lzo_wrkmem);
		return lzolen;
	} else if(level < 10) {
		unsigned long destlen = MAXSIZE;
		if(compress2(dest, &destlen, source, len, level) == Z_OK)
			return destlen;
		else
			return -1;
	} else {
		lzo_uint lzolen = MAXSIZE;
		lzo1x_999_compress(source, len, dest, &lzolen, lzo_wrkmem);
		return lzolen;
	}
	
	return -1;
}

static length_t uncompress_packet(uint8_t *dest, const uint8_t *source, length_t len, int level)
{
	if(level > 9) {
		lzo_uint lzolen = MAXSIZE;
		if(lzo1x_decompress_safe(source, len, dest, &lzolen, NULL) == LZO_E_OK)
			return lzolen;
		else
			return -1;
	} else {
		unsigned long destlen = MAXSIZE;
		if(uncompress(dest, &destlen, source, len) == Z_OK)
			return destlen;
		else
			return -1;
	}
	
	return -1;
}

/* VPN packet I/O */

static void receive_packet(node_t *n, vpn_packet_t *packet)
{
	cp();

	ifdebug(TRAFFIC) logger(LOG_DEBUG, _("Received packet of %d bytes from %s (%s)"),
			   packet->len, n->name, n->hostname);

	route_incoming(n, packet);
}

static void receive_udppacket(node_t *n, vpn_packet_t *inpkt)
{
	vpn_packet_t pkt1, pkt2;
	vpn_packet_t *pkt[] = { &pkt1, &pkt2, &pkt1, &pkt2 };
	int nextpkt = 0;
	vpn_packet_t *outpkt = pkt[0];
	int outlen, outpad;
	char hmac[EVP_MAX_MD_SIZE];
	int i;

	cp();

	/* Check packet length */

	if(inpkt->len < sizeof(inpkt->seqno) + myself->maclength) {
		ifdebug(TRAFFIC) logger(LOG_DEBUG, _("Got too short packet from %s (%s)"),
					n->name, n->hostname);
		return;
	}

	/* Check the message authentication code */

	if(myself->digest && myself->maclength) {
		inpkt->len -= myself->maclength;
		HMAC(myself->digest, myself->key, myself->keylength,
			 (char *) &inpkt->seqno, inpkt->len, hmac, NULL);

		if(memcmp(hmac, (char *) &inpkt->seqno + inpkt->len, myself->maclength)) {
			ifdebug(TRAFFIC) logger(LOG_DEBUG, _("Got unauthenticated packet from %s (%s)"),
					   n->name, n->hostname);
			return;
		}
	}

	/* Decrypt the packet */

	if(myself->cipher) {
		outpkt = pkt[nextpkt++];

		if(!EVP_DecryptInit_ex(&packet_ctx, NULL, NULL, NULL, NULL)
				|| !EVP_DecryptUpdate(&packet_ctx, (char *) &outpkt->seqno, &outlen,
					(char *) &inpkt->seqno, inpkt->len)
				|| !EVP_DecryptFinal_ex(&packet_ctx, (char *) &outpkt->seqno + outlen, &outpad)) {
			ifdebug(TRAFFIC) logger(LOG_DEBUG, _("Error decrypting packet from %s (%s): %s"),
						n->name, n->hostname, ERR_error_string(ERR_get_error(), NULL));
			return;
		}
		
		outpkt->len = outlen + outpad;
		inpkt = outpkt;
	}

	/* Check the sequence number */

	inpkt->len -= sizeof(inpkt->seqno);
	inpkt->seqno = ntohl(inpkt->seqno);

	if(inpkt->seqno != n->received_seqno + 1) {
		if(inpkt->seqno >= n->received_seqno + sizeof(n->late) * 8) {
			logger(LOG_WARNING, _("Lost %d packets from %s (%s)"),
					   inpkt->seqno - n->received_seqno - 1, n->name, n->hostname);
			
			memset(n->late, 0, sizeof(n->late));
		} else if (inpkt->seqno <= n->received_seqno) {
			if(inpkt->seqno <= n->received_seqno - sizeof(n->late) * 8 || !(n->late[(inpkt->seqno / 8) % sizeof(n->late)] & (1 << inpkt->seqno % 8))) {
				logger(LOG_WARNING, _("Got late or replayed packet from %s (%s), seqno %d, last received %d"),
					   n->name, n->hostname, inpkt->seqno, n->received_seqno);
			} else
				for(i = n->received_seqno + 1; i < inpkt->seqno; i++)
					n->late[(inpkt->seqno / 8) % sizeof(n->late)] |= 1 << i % 8;
		}
	}
	
	n->received_seqno = inpkt->seqno;
	n->late[(n->received_seqno / 8) % sizeof(n->late)] &= ~(1 << n->received_seqno % 8);
			
	if(n->received_seqno > MAX_SEQNO)
		keyexpires = 0;

	/* Decompress the packet */

	if(myself->compression) {
		outpkt = pkt[nextpkt++];

		if((outpkt->len = uncompress_packet(outpkt->data, inpkt->data, inpkt->len, myself->compression)) < 0) {
			ifdebug(TRAFFIC) logger(LOG_ERR, _("Error while uncompressing packet from %s (%s)"),
				  		 n->name, n->hostname);
			return;
		}

		inpkt = outpkt;
	}

	if(n->connection)
		n->connection->last_ping_time = now;

	receive_packet(n, inpkt);
}

void receive_tcppacket(connection_t *c, char *buffer, int len)
{
	vpn_packet_t outpkt;

	cp();

	outpkt.len = len;
	memcpy(outpkt.data, buffer, len);

	receive_packet(c->node, &outpkt);
}

static void send_udppacket(node_t *n, vpn_packet_t *inpkt)
{
	vpn_packet_t pkt1, pkt2;
	vpn_packet_t *pkt[] = { &pkt1, &pkt2, &pkt1, &pkt2 };
	int nextpkt = 0;
	vpn_packet_t *outpkt;
	int origlen;
	int outlen, outpad;
	vpn_packet_t *copy;
	static int priority = 0;
	int origpriority;
	int sock;

	cp();

	/* Make sure we have a valid key */

	if(!n->status.validkey) {
		ifdebug(TRAFFIC) logger(LOG_INFO,
				   _("No valid key known yet for %s (%s), queueing packet"),
				   n->name, n->hostname);

		/* Since packet is on the stack of handle_tap_input(), we have to make a copy of it first. */

		copy = xmalloc(sizeof(vpn_packet_t));
		memcpy(copy, inpkt, sizeof(vpn_packet_t));

		list_insert_tail(n->queue, copy);

		if(n->queue->count > MAXQUEUELENGTH)
			list_delete_head(n->queue);

		if(!n->status.waitingforkey)
			send_req_key(n->nexthop->connection, myself, n);

		n->status.waitingforkey = true;

		return;
	}

	origlen = inpkt->len;
	origpriority = inpkt->priority;

	/* Compress the packet */

	if(n->compression) {
		outpkt = pkt[nextpkt++];

		if((outpkt->len = compress_packet(outpkt->data, inpkt->data, inpkt->len, n->compression)) < 0) {
			ifdebug(TRAFFIC) logger(LOG_ERR, _("Error while compressing packet to %s (%s)"),
				   n->name, n->hostname);
			return;
		}

		inpkt = outpkt;
	}

	/* Add sequence number */

	inpkt->seqno = htonl(++(n->sent_seqno));
	inpkt->len += sizeof(inpkt->seqno);

	/* Encrypt the packet */

	if(n->cipher) {
		outpkt = pkt[nextpkt++];

		if(!EVP_EncryptInit_ex(&n->packet_ctx, NULL, NULL, NULL, NULL)
				|| !EVP_EncryptUpdate(&n->packet_ctx, (char *) &outpkt->seqno, &outlen,
					(char *) &inpkt->seqno, inpkt->len)
				|| !EVP_EncryptFinal_ex(&n->packet_ctx, (char *) &outpkt->seqno + outlen, &outpad)) {
			ifdebug(TRAFFIC) logger(LOG_ERR, _("Error while encrypting packet to %s (%s): %s"),
						n->name, n->hostname, ERR_error_string(ERR_get_error(), NULL));
			return;
		}

		outpkt->len = outlen + outpad;
		inpkt = outpkt;
	}

	/* Add the message authentication code */

	if(n->digest && n->maclength) {
		HMAC(n->digest, n->key, n->keylength, (char *) &inpkt->seqno,
			 inpkt->len, (char *) &inpkt->seqno + inpkt->len, &outlen);
		inpkt->len += n->maclength;
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
		ifdebug(TRAFFIC) logger(LOG_DEBUG, _("Setting outgoing packet priority to %d"), priority);
		if(setsockopt(listen_socket[sock].udp, SOL_IP, IP_TOS, &priority, sizeof(priority)))	/* SO_PRIORITY doesn't seem to work */
			logger(LOG_ERR, _("System call `%s' failed: %s"), "setsockopt", strerror(errno));
	}
#endif

	if((sendto(listen_socket[sock].udp, (char *) &inpkt->seqno, inpkt->len, 0, &(n->address.sa), SALEN(n->address.sa))) < 0) {
		logger(LOG_ERR, _("Error sending packet to %s (%s): %s"), n->name, n->hostname, strerror(errno));
		return;
	}

	inpkt->len = origlen;
}

/*
  send a packet to the given vpn ip.
*/
void send_packet(const node_t *n, vpn_packet_t *packet)
{
	node_t *via;

	cp();

	ifdebug(TRAFFIC) logger(LOG_ERR, _("Sending packet of %d bytes to %s (%s)"),
			   packet->len, n->name, n->hostname);

	if(n == myself) {
		ifdebug(TRAFFIC) logger(LOG_NOTICE, _("Packet is looping back to us!"));
		return;
	}

	if(!n->status.reachable) {
		ifdebug(TRAFFIC) logger(LOG_INFO, _("Node %s (%s) is not reachable"),
				   n->name, n->hostname);
		return;
	}

	via = (n->via == myself) ? n->nexthop : n->via;

	if(via != n)
		ifdebug(TRAFFIC) logger(LOG_ERR, _("Sending packet to %s via %s (%s)"),
			   n->name, via->name, n->via->hostname);

	if((myself->options | via->options) & OPTION_TCPONLY) {
		if(!send_tcppacket(via->connection, packet))
			terminate_connection(via->connection, true);
	} else
		send_udppacket(via, packet);
}

/* Broadcast a packet using the minimum spanning tree */

void broadcast_packet(const node_t *from, vpn_packet_t *packet)
{
	avl_node_t *node;
	connection_t *c;

	cp();

	ifdebug(TRAFFIC) logger(LOG_INFO, _("Broadcasting packet of %d bytes from %s (%s)"),
			   packet->len, from->name, from->hostname);

	for(node = connection_tree->head; node; node = node->next) {
		c = node->data;

		if(c->status.active && c->status.mst && c != from->nexthop->connection)
			send_packet(c->node, packet);
	}
}

void flush_queue(node_t *n)
{
	list_node_t *node, *next;

	cp();

	ifdebug(TRAFFIC) logger(LOG_INFO, _("Flushing queue for %s (%s)"), n->name, n->hostname);

	for(node = n->queue->head; node; node = next) {
		next = node->next;
		send_udppacket(n, node->data);
		list_delete_node(n->queue, node);
	}
}

void handle_incoming_vpn_data(int sock)
{
	vpn_packet_t pkt;
	char *hostname;
	sockaddr_t from;
	socklen_t fromlen = sizeof(from);
	node_t *n;

	cp();

	pkt.len = recvfrom(sock, (char *) &pkt.seqno, MAXSIZE, 0, &from.sa, &fromlen);

	if(pkt.len < 0) {
		logger(LOG_ERR, _("Receiving packet failed: %s"), strerror(errno));
		return;
	}

	sockaddrunmap(&from);		/* Some braindead IPv6 implementations do stupid things. */

	n = lookup_node_udp(&from);

	if(!n) {
		hostname = sockaddr2hostname(&from);
		logger(LOG_WARNING, _("Received UDP packet from unknown source %s"),
			   hostname);
		free(hostname);
		return;
	}

	receive_udppacket(n, &pkt);
}
