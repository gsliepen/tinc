/*
    meta.c -- handle the meta communication
    Copyright (C) 2000-2003 Guus Sliepen <guus@sliepen.eu.org>,
                  2000-2003 Ivo Timmermans <ivo@o2w.nl>

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

    $Id: meta.c,v 1.1.2.44 2003/08/28 21:05:10 guus Exp $
*/

#include "system.h"

#include <openssl/evp.h>

#include "avl_tree.h"
#include "connection.h"
#include "logger.h"
#include "meta.h"
#include "net.h"
#include "protocol.h"
#include "system.h"
#include "utils.h"

bool send_meta(connection_t *c, const char *buffer, int length)
{
	const char *bufp;
	int outlen;
	char outbuf[MAXBUFSIZE];
	int result;

	cp();

	ifdebug(META) logger(LOG_DEBUG, _("Sending %d bytes of metadata to %s (%s)"), length,
			   c->name, c->hostname);

	if(c->status.encryptout) {
		EVP_EncryptUpdate(c->outctx, outbuf, &outlen, buffer, length);
		bufp = outbuf;
		length = outlen;
	} else
		bufp = buffer;

	while(length) {
		result = send(c->socket, bufp, length, 0);
		if(result <= 0) {
			if(!errno || errno == EPIPE) {
				ifdebug(CONNECTIONS) logger(LOG_NOTICE, _("Connection closed by %s (%s)"),
						   c->name, c->hostname);
			} else if(errno == EINTR)
				continue;
			else
				logger(LOG_ERR, _("Sending meta data to %s (%s) failed: %s"), c->name,
					   c->hostname, strerror(errno));
			return false;
		}
		bufp += result;
		length -= result;
	}
	
	return true;
}

void broadcast_meta(connection_t *from, const char *buffer, int length)
{
	avl_node_t *node;
	connection_t *c;

	cp();

	for(node = connection_tree->head; node; node = node->next) {
		c = node->data;

		if(c != from && c->status.active)
			send_meta(c, buffer, length);
	}
}

bool receive_meta(connection_t *c)
{
	int oldlen, i;
	int lenin, reqlen;
	bool decrypted = false;
	char inbuf[MAXBUFSIZE];

	cp();

	/* Strategy:
	   - Read as much as possible from the TCP socket in one go.
	   - Decrypt it.
	   - Check if a full request is in the input buffer.
	   - If yes, process request and remove it from the buffer,
	   then check again.
	   - If not, keep stuff in buffer and exit.
	 */

	lenin = recv(c->socket, c->buffer + c->buflen, MAXBUFSIZE - c->buflen, 0);

	if(lenin <= 0) {
		if(!lenin || !errno) {
			ifdebug(CONNECTIONS) logger(LOG_NOTICE, _("Connection closed by %s (%s)"),
					   c->name, c->hostname);
		} else if(errno == EINTR)
			return true;
		else
			logger(LOG_ERR, _("Metadata socket read error for %s (%s): %s"),
				   c->name, c->hostname, strerror(errno));

		return false;
	}

	oldlen = c->buflen;
	c->buflen += lenin;

	while(lenin) {
		/* Decrypt */

		if(c->status.decryptin && !decrypted) {
			EVP_DecryptUpdate(c->inctx, inbuf, &lenin, c->buffer + oldlen, lenin);
			memcpy(c->buffer + oldlen, inbuf, lenin);
			decrypted = true;
		}

		/* Are we receiving a TCPpacket? */

		if(c->tcplen) {
			if(c->tcplen <= c->buflen) {
				receive_tcppacket(c, c->buffer, c->tcplen);

				c->buflen -= c->tcplen;
				lenin -= c->tcplen;
				memmove(c->buffer, c->buffer + c->tcplen, c->buflen);
				oldlen = 0;
				c->tcplen = 0;
				continue;
			} else {
				break;
			}
		}

		/* Otherwise we are waiting for a request */

		reqlen = 0;

		for(i = oldlen; i < c->buflen; i++) {
			if(c->buffer[i] == '\n') {
				c->buffer[i] = '\0';	/* replace end-of-line by end-of-string so we can use sscanf */
				reqlen = i + 1;
				break;
			}
		}

		if(reqlen) {
			c->reqlen = reqlen;
			if(!receive_request(c))
				return false;

			c->buflen -= reqlen;
			lenin -= reqlen;
			memmove(c->buffer, c->buffer + reqlen, c->buflen);
			oldlen = 0;
			continue;
		} else {
			break;
		}
	}

	if(c->buflen >= MAXBUFSIZE) {
		logger(LOG_ERR, _("Metadata read buffer overflow for %s (%s)"),
			   c->name, c->hostname);
		return false;
	}

	c->last_ping_time = now;

	return true;
}
