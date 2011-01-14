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
		char outbuf[length];
		size_t outlen = length;

		if(!cipher_encrypt(&c->outcipher, buffer, length, outbuf, &outlen, false) || outlen != length) {
			logger(LOG_ERR, "Error while encrypting metadata to %s (%s)",
					c->name, c->hostname);
			return false;
		}
		
		write(c->socket, outbuf, length);
	} else {
		write(c->socket, buffer, length);
	}

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

static bool process_meta(connection_t *c, char *reqbuf, int *len) {
	while(*len) {
		if(c->tcplen) {
			if(c->tcplen > *len)
				break;

			receive_tcppacket(c, reqbuf, c->tcplen);

			memmove(reqbuf, reqbuf, *len - c->tcplen);
			*len -= c->tcplen;
		} else {
			char *end = memchr(reqbuf, '\n', *len);
			if(!end)
				break;
			else
				*end++ = 0;

			if(!receive_request(c, reqbuf))
				return false;

			memmove(reqbuf, end, *len - (end - reqbuf));
			*len -= end - reqbuf;
		}
	}

	return true;
}
			
bool receive_meta(connection_t *c) {
	int inlen;
	int reqlen = 0;
	char inbuf[MAXBUFSIZE];
	char reqbuf[MAXBUFSIZE];

	/* Strategy:
	   - Read as much as possible from the TCP socket in one go.
	   - Decrypt it if necessary.
	   - Check if a full request is in the request buffer.
	   - If yes, process request and remove it from the buffer, then check again.
	   - If not, try to read more.
	 */

	while(true) {
		inlen = recv(c->socket, inbuf, sizeof inbuf - reqlen, 0);

		if(inlen <= 0) {
			if(!inlen || !errno) {
				ifdebug(CONNECTIONS) logger(LOG_NOTICE, "Connection closed by %s (%s)",
						   c->name, c->hostname);
			} else if(sockwouldblock(sockerrno))
				continue;
			else
				logger(LOG_ERR, "Metadata socket read error for %s (%s): %s",
					   c->name, c->hostname, sockstrerror(sockerrno));
			return false;
		}

		while(inlen) {
			if(!c->status.decryptin) {
				char *end = memchr(inbuf, '\n', inlen);
				if(!end)
					end = inbuf + inlen;
				else
					end++;
				memcpy(reqbuf + reqlen, inbuf, end - inbuf);
				reqlen += end - inbuf;

				if(!process_meta(c, reqbuf, &reqlen))
					return false;

				memmove(inbuf, end, inlen - (end - inbuf));
				inlen -= end - inbuf;
			} else {
				size_t outlen = inlen;

				if(!cipher_decrypt(&c->incipher, inbuf, inlen, reqbuf + reqlen, &outlen, false) || inlen != outlen) {
					logger(LOG_ERR, "Error while decrypting metadata from %s (%s)", c->name, c->hostname);
					return false;
				}

				reqlen += inlen;
				inlen = 0;

				if(!process_meta(c, reqbuf, &reqlen))
					return false;
			}
		}
	}
}
