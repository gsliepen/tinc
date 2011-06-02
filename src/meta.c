/*
    meta.c -- handle the meta communication
    Copyright (C) 2000-2009 Guus Sliepen <guus@tinc-vpn.org>,
                  2000-2005 Ivo Timmermans
                  2006      Scott Lamb <slamb@slamb.org>

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

#include "splay_tree.h"
#include "cipher.h"
#include "connection.h"
#include "logger.h"
#include "meta.h"
#include "net.h"
#include "protocol.h"
#include "utils.h"
#include "xalloc.h"

bool send_meta(connection_t *c, const char *buffer, int length) {
	if(!c) {
		logger(LOG_ERR, "send_meta() called with NULL pointer!");
		abort();
	}

	ifdebug(META) logger(LOG_DEBUG, "Sending %d bytes of metadata to %s (%s)", length,
			   c->name, c->hostname);

	/* Add our data to buffer */
	if(c->status.encryptout) {
		size_t outlen = length;

		if(!cipher_encrypt(&c->outcipher, buffer, length, buffer_prepare(&c->outbuf, length), &outlen, false) || outlen != length) {
			logger(LOG_ERR, "Error while encrypting metadata to %s (%s)",
					c->name, c->hostname);
			return false;
		}

	} else {
		buffer_add(&c->outbuf, buffer, length);
	}

	event_add(&c->outevent, NULL);

	return true;
}

void broadcast_meta(connection_t *from, const char *buffer, int length) {
	splay_node_t *node;
	connection_t *c;

	for(node = connection_tree->head; node; node = node->next) {
		c = node->data;

		if(c != from && c->status.active)
			send_meta(c, buffer, length);
	}
}

bool receive_meta(connection_t *c) {
	int inlen;
	char inbuf[MAXBUFSIZE];
	char *bufp = inbuf, *endp;

	/* Strategy:
	   - Read as much as possible from the TCP socket in one go.
	   - Decrypt it.
	   - Check if a full request is in the input buffer.
	   - If yes, process request and remove it from the buffer,
	   then check again.
	   - If not, keep stuff in buffer and exit.
	 */

	buffer_compact(&c->inbuf, MAXBUFSIZE);

	if(sizeof inbuf <= c->inbuf.len) {
		logger(LOG_ERR, "Input buffer full for %s (%s)", c->name, c->hostname);
		return false;
	}

	inlen = recv(c->socket, inbuf, sizeof inbuf - c->inbuf.len, 0);

	if(inlen <= 0) {
		if(!inlen || !errno) {
			ifdebug(CONNECTIONS) logger(LOG_NOTICE, "Connection closed by %s (%s)",
					   c->name, c->hostname);
		} else if(sockwouldblock(sockerrno))
			return true;
		else
			logger(LOG_ERR, "Metadata socket read error for %s (%s): %s",
				   c->name, c->hostname, sockstrerror(sockerrno));
		return false;
	}

	do {
		if(!c->status.decryptin) {
			endp = memchr(bufp, '\n', inlen);
			if(endp)
				endp++;
			else
				endp = bufp + inlen;

			buffer_add(&c->inbuf, bufp, endp - bufp);

			inlen -= endp - bufp;
			bufp = endp;
		} else {
			size_t outlen = inlen;
			ifdebug(META) logger(LOG_DEBUG, "Received encrypted %d bytes", inlen);

			if(!cipher_decrypt(&c->incipher, bufp, inlen, buffer_prepare(&c->inbuf, inlen), &outlen, false) || inlen != outlen) {
				logger(LOG_ERR, "Error while decrypting metadata from %s (%s)",
					   c->name, c->hostname);
				return false;
			}

			inlen = 0;
		}

		while(c->inbuf.len) {
			/* Are we receiving a TCPpacket? */

			if(c->tcplen) {
				char *tcpbuffer = buffer_read(&c->inbuf, c->tcplen);
				if(tcpbuffer) {
					receive_tcppacket(c, tcpbuffer, c->tcplen);
					c->tcplen = 0;
					continue;
				} else {
					break;
				}
			}

			/* Otherwise we are waiting for a request */

			char *request = buffer_readline(&c->inbuf);
			if(request) {
				bool result = receive_request(c, request);
				if(!result)
					return false;
				continue;
			} else {
				break;
			}
		}
	} while(inlen);

	return true;
}
