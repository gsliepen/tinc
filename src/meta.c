/*
    meta.c -- handle the meta communication
    Copyright (C) 2000-2006 Guus Sliepen <guus@tinc-vpn.org>,
                  2000-2005 Ivo Timmermans

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

    $Id$
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
	cp();

	ifdebug(META) logger(LOG_DEBUG, _("Sending %d bytes of metadata to %s (%s)"), length, c->name, c->hostname);

	/* Add our data to buffer */
	if(c->status.encryptout) {
		char outbuf[length];
		size_t outlen = length;

		if(!cipher_encrypt(&c->outcipher, buffer, length, outbuf, &outlen, false) || outlen != length) {
			logger(LOG_ERR, _("Error while encrypting metadata to %s (%s)"), c->name, c->hostname);
			return false;
		}
		
		bufferevent_write(c->buffer, (void *)outbuf, length);
	} else {
		bufferevent_write(c->buffer, (void *)buffer, length);
	}

	return true;
}

void broadcast_meta(connection_t *from, const char *buffer, int length) {
	splay_node_t *node;
	connection_t *c;

	cp();

	for(node = connection_tree->head; node; node = node->next) {
		c = node->data;

		if(c != from && c->status.active)
			send_meta(c, buffer, length);
	}
}

bool receive_meta(connection_t *c) {
	size_t inlen;
	char inbuf[MAXBUFSIZE];
	char *bufp = inbuf, *endp;

	cp();

	/* Strategy:
	   - Read as much as possible from the TCP socket in one go.
	   - Decrypt it.
	   - Check if a full request is in the input buffer.
	   - If yes, process request and remove it from the buffer,
	   then check again.
	   - If not, keep stuff in buffer and exit.
	 */

	inlen = recv(c->socket, inbuf, sizeof inbuf, 0);

	if(inlen <= 0) {
		logger(LOG_ERR, _("Receive callback called for %s (%s) but no data to receive: %s"), c->name, c->hostname, strerror(errno));
		return false;
	}

	do {
		if(!c->status.decryptin) {
			endp = memchr(bufp, '\n', inlen);
			if(endp)
				endp++;
			else
				endp = bufp + inlen;

			evbuffer_add(c->buffer->input, bufp, endp - bufp);

			inlen -= endp - bufp;
			bufp = endp;
		} else {
			size_t outlen = inlen;
			evbuffer_expand(c->buffer->input, inlen);

			if(!cipher_decrypt(&c->incipher, bufp, inlen, c->buffer->input->buffer, &outlen, false) || inlen != outlen) {
				logger(LOG_ERR, _("Error while decrypting metadata from %s (%s)"), c->name, c->hostname);
				return false;
			}

			c->buffer->input->off += inlen;
			inlen = 0;
		}

		while(c->buffer->input->off) {
			/* Are we receiving a TCPpacket? */

			if(c->tcplen) {
				if(c->tcplen <= c->buffer->input->off) {
					receive_tcppacket(c, (char *)c->buffer->input->buffer, c->tcplen);
					evbuffer_drain(c->buffer->input, c->tcplen);
					c->tcplen = 0;
					continue;
				} else {
					break;
				}
			}

			/* Otherwise we are waiting for a request */

			char *request = evbuffer_readline(c->buffer->input);
			if(request) {
				bool result = receive_request(c, request);
				free(request);
				if(!result)
					return false;
				continue;
			} else {
				break;
			}
		}
	} while(inlen);

	c->last_ping_time = time(NULL);

	return true;
}
