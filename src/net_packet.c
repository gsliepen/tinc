/*
    net_packet.c -- Handles in- and outgoing VPN packets
    Copyright (C) 1998-2002 Ivo Timmermans <itimmermans@bigfoot.com>,
                  2000-2002 Guus Sliepen <guus@sliepen.warande.net>

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

    $Id: net_packet.c,v 1.1.2.13 2002/03/27 15:01:37 guus Exp $
*/

#include "config.h"

#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#ifdef HAVE_LINUX
 #include <netinet/ip.h>
 #include <netinet/tcp.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <sys/time.h>
#include <sys/types.h>
#include <syslog.h>
#include <unistd.h>
#include <sys/ioctl.h>
/* SunOS really wants sys/socket.h BEFORE net/if.h,
   and FreeBSD wants these lines below the rest. */
#include <arpa/inet.h>
#include <sys/socket.h>
#include <net/if.h>

#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/hmac.h>

#ifndef HAVE_RAND_PSEUDO_BYTES
#define RAND_pseudo_bytes RAND_bytes
#endif

#include <zlib.h>

#include <utils.h>
#include <xalloc.h>
#include <avl_tree.h>
#include <list.h>

#include "conf.h"
#include "connection.h"
#include "meta.h"
#include "net.h"
#include "netutl.h"
#include "process.h"
#include "protocol.h"
#include "subnet.h"
#include "graph.h"
#include "process.h"
#include "route.h"
#include "device.h"
#include "event.h"

#include "system.h"

int keylifetime = 0;
int keyexpires = 0;

#define MAX_SEQNO 1073741824

/* VPN packet I/O */

void receive_udppacket(node_t *n, vpn_packet_t *inpkt)
{
  vpn_packet_t pkt1, pkt2;
  vpn_packet_t *pkt[] = {&pkt1, &pkt2, &pkt1, &pkt2};
  int nextpkt = 0;
  vpn_packet_t *outpkt = pkt[0];
  int outlen, outpad;
  long int complen = MTU + 12;
  EVP_CIPHER_CTX ctx;
  char hmac[EVP_MAX_MD_SIZE];
cp
  /* Check the message authentication code */

  if(myself->digest && myself->maclength)
    {
      inpkt->len -= myself->maclength;
      HMAC(myself->digest, myself->key, myself->keylength, (char *)&inpkt->seqno, inpkt->len, hmac, NULL);
      if(memcmp(hmac, (char *)&inpkt->seqno + inpkt->len, myself->maclength))
        {
          if(debug_lvl >= DEBUG_TRAFFIC)
            syslog(LOG_DEBUG, _("Got unauthenticated packet from %s (%s)"), n->name, n->hostname);
          return;
        }
    }

  /* Decrypt the packet */

  if(myself->cipher)
  {
    outpkt = pkt[nextpkt++];

    EVP_DecryptInit(&ctx, myself->cipher, myself->key, myself->key + myself->cipher->key_len);
    EVP_DecryptUpdate(&ctx, (char *)&outpkt->seqno, &outlen, (char *)&inpkt->seqno, inpkt->len);
    EVP_DecryptFinal(&ctx, (char *)&outpkt->seqno + outlen, &outpad);

    outpkt->len = outlen + outpad;
    inpkt = outpkt;
  }

  /* Check the sequence number */

  inpkt->len -= sizeof(inpkt->seqno);
  inpkt->seqno = ntohl(inpkt->seqno);

  if(inpkt->seqno <= n->received_seqno)
  {
    if(debug_lvl >= DEBUG_TRAFFIC)
      syslog(LOG_DEBUG, _("Got late or replayed packet from %s (%s), seqno %d"), n->name, n->hostname, inpkt->seqno);
    return;
  }
  
  n->received_seqno = inpkt->seqno;

  if(n->received_seqno > MAX_SEQNO)
    keyexpires = 0;

  /* Decompress the packet */
  
  if(myself->compression)
  {
    outpkt = pkt[nextpkt++];

    if(uncompress(outpkt->data, &complen, inpkt->data, inpkt->len) != Z_OK)
    {
      syslog(LOG_ERR, _("Error while uncompressing packet from %s (%s)"), n->name, n->hostname);
      return;
    }
    
    outpkt->len = complen;
    inpkt = outpkt;
  }

  receive_packet(n, inpkt);
cp
}

void receive_tcppacket(connection_t *c, char *buffer, int len)
{
  vpn_packet_t outpkt;
cp
  outpkt.len = len;
  memcpy(outpkt.data, buffer, len);

  receive_packet(c->node, &outpkt);
cp
}

void receive_packet(node_t *n, vpn_packet_t *packet)
{
cp
  if(debug_lvl >= DEBUG_TRAFFIC)
    syslog(LOG_DEBUG, _("Received packet of %d bytes from %s (%s)"), packet->len, n->name, n->hostname);

  route_incoming(n, packet);
cp
}

void send_udppacket(node_t *n, vpn_packet_t *inpkt)
{
  vpn_packet_t pkt1, pkt2;
  vpn_packet_t *pkt[] = {&pkt1, &pkt2, &pkt1, &pkt2};
  int nextpkt = 0;
  vpn_packet_t *outpkt;
  int origlen;
  int outlen, outpad;
  long int complen = MTU + 12;
  EVP_CIPHER_CTX ctx;
  vpn_packet_t *copy;
  static int priority = 0;
  int origpriority;
  int sock;
cp
  /* Make sure we have a valid key */

  if(!n->status.validkey)
    {
      if(debug_lvl >= DEBUG_TRAFFIC)
        syslog(LOG_INFO, _("No valid key known yet for %s (%s), queueing packet"),
               n->name, n->hostname);

      /* Since packet is on the stack of handle_tap_input(),
         we have to make a copy of it first. */

      copy = xmalloc(sizeof(vpn_packet_t));
      memcpy(copy, inpkt, sizeof(vpn_packet_t));

      list_insert_tail(n->queue, copy);

      if(n->queue->count > MAXQUEUELENGTH)
        list_delete_head(n->queue);

      if(!n->status.waitingforkey)
        send_req_key(n->nexthop->connection, myself, n);

      n->status.waitingforkey = 1;

      return;
    }

  origlen = inpkt->len;
  origpriority = inpkt->priority;

  /* Compress the packet */

  if(n->compression)
  {
    outpkt = pkt[nextpkt++];

    if(compress2(outpkt->data, &complen, inpkt->data, inpkt->len, n->compression) != Z_OK)
    {
      syslog(LOG_ERR, _("Error while compressing packet to %s (%s)"), n->name, n->hostname);
      return;
    }
    
    outpkt->len = complen;
    inpkt = outpkt;
  }

  /* Add sequence number */

  inpkt->seqno = htonl(++(n->sent_seqno));
  inpkt->len += sizeof(inpkt->seqno);

  /* Encrypt the packet */

  if(n->cipher)
  {
    outpkt = pkt[nextpkt++];

    EVP_EncryptInit(&ctx, n->cipher, n->key, n->key + n->cipher->key_len);
    EVP_EncryptUpdate(&ctx, (char *)&outpkt->seqno, &outlen, (char *)&inpkt->seqno, inpkt->len);
    EVP_EncryptFinal(&ctx, (char *)&outpkt->seqno + outlen, &outpad);

    outpkt->len = outlen + outpad;
    inpkt = outpkt;
  }

  /* Add the message authentication code */

  if(n->digest && n->maclength)
    {
      HMAC(n->digest, n->key, n->keylength, (char *)&inpkt->seqno, inpkt->len, (char *)&inpkt->seqno + inpkt->len, &outlen);
      inpkt->len += n->maclength;
    }

  /* Determine which socket we have to use */

  for(sock = 0; sock < listen_sockets; sock++)
    if(n->address.sa.sa_family == listen_socket[sock].sa.sa.sa_family)
      break;

  if(sock >= listen_sockets)
    sock = 0;  /* If none is available, just use the first and hope for the best. */
  
  /* Send the packet */

#if defined(SOL_IP) && defined(IP_TOS)
  if(priorityinheritance && origpriority != priority && listen_socket[sock].sa.sa.sa_family == AF_INET)
    {
      priority = origpriority;
      if(debug_lvl >= DEBUG_TRAFFIC)
        syslog(LOG_DEBUG, _("Setting outgoing packet priority to %d"), priority);
      if(setsockopt(sock, SOL_IP, IP_TOS, &priority, sizeof(priority))) /* SO_PRIORITY doesn't seem to work */
	syslog(LOG_ERR, _("System call `%s' failed: %s"), "setsockopt", strerror(errno));
    }
#endif

  if((sendto(listen_socket[sock].udp, (char *)&inpkt->seqno, inpkt->len, 0, &(n->address.sa), SALEN(n->address.sa))) < 0)
    {
      syslog(LOG_ERR, _("Error sending packet to %s (%s): %s"),
             n->name, n->hostname, strerror(errno));
      return;
    }
  
  inpkt->len = origlen;
cp
}

/*
  send a packet to the given vpn ip.
*/
void send_packet(node_t *n, vpn_packet_t *packet)
{
  node_t *via;
cp
  if(debug_lvl >= DEBUG_TRAFFIC)
    syslog(LOG_ERR, _("Sending packet of %d bytes to %s (%s)"),
           packet->len, n->name, n->hostname);

  if(n == myself)
    {
      if(debug_lvl >= DEBUG_TRAFFIC)
        {
          syslog(LOG_NOTICE, _("Packet is looping back to us!"));
        }

      return;
    }
 
  if(!n->status.reachable)
    {
      if(debug_lvl >= DEBUG_TRAFFIC)
        syslog(LOG_INFO, _("Node %s (%s) is not reachable"),
               n->name, n->hostname);
      return;
    }

  via = (n->via == myself)?n->nexthop:n->via;

  if(via != n && debug_lvl >= DEBUG_TRAFFIC)
    syslog(LOG_ERR, _("Sending packet to %s via %s (%s)"),
           n->name, via->name, n->via->hostname);

  if((myself->options | via->options) & OPTION_TCPONLY)
    {
      if(send_tcppacket(via->connection, packet))
        terminate_connection(via->connection, 1);
    }
  else
    send_udppacket(via, packet);
}

/* Broadcast a packet using the minimum spanning tree */

void broadcast_packet(node_t *from, vpn_packet_t *packet)
{
  avl_node_t *node;
  connection_t *c;
cp
  if(debug_lvl >= DEBUG_TRAFFIC)
    syslog(LOG_INFO, _("Broadcasting packet of %d bytes from %s (%s)"),
           packet->len, from->name, from->hostname);

  for(node = connection_tree->head; node; node = node->next)
    {
      c = (connection_t *)node->data;
      if(c->status.active && c->status.mst && c != from->nexthop->connection)
        send_packet(c->node, packet);
    }
cp
}

void flush_queue(node_t *n)
{
  list_node_t *node, *next;
cp
  if(debug_lvl >= DEBUG_TRAFFIC)
    syslog(LOG_INFO, _("Flushing queue for %s (%s)"), n->name, n->hostname);

  for(node = n->queue->head; node; node = next)
    {
      next = node->next;
      send_udppacket(n, (vpn_packet_t *)node->data);
      list_delete_node(n->queue, node);
    }
cp
}

void handle_incoming_vpn_data(int sock)
{
  vpn_packet_t pkt;
  int x, l = sizeof(x);
  char *hostname;
  sockaddr_t from;
  socklen_t fromlen = sizeof(from);
  node_t *n;
cp
  if(getsockopt(sock, SOL_SOCKET, SO_ERROR, &x, &l) < 0)
    {
      syslog(LOG_ERR, _("This is a bug: %s:%d: %d:%s"),
             __FILE__, __LINE__, sock, strerror(errno));
      cp_trace();
      exit(1);
    }
  if(x)
    {
      syslog(LOG_ERR, _("Incoming data socket error: %s"), strerror(x));
      return;
    }

  if((pkt.len = recvfrom(sock, (char *)&pkt.seqno, MAXSIZE, 0, &from.sa, &fromlen)) <= 0)
    {
      syslog(LOG_ERR, _("Receiving packet failed: %s"), strerror(errno));
      return;
    }

  sockaddrunmap(&from);  /* Some braindead IPv6 implementations do stupid things. */

  n = lookup_node_udp(&from);

  if(!n)
    {
      hostname = sockaddr2hostname(&from);
      syslog(LOG_WARNING, _("Received UDP packet from unknown source %s"), hostname);
      free(hostname);
      return;
    }

  if(n->connection)
    n->connection->last_ping_time = now;

  receive_udppacket(n, &pkt);
cp
}

