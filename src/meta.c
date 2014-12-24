/*
    meta.c -- handle the meta communication
    Copyright (C) 2000-2014 Guus Sliepen <guus@tinc-vpn.org>,
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

#include "cipher.h"
#include "connection.h"
#include "logger.h"
#include "meta.h"
#include "net.h"
#include "protocol.h"
#include "utils.h"
#include "xalloc.h"

bool send_meta_sptps(void *handle, uint8_t type, const void *buffer, size_t length) {
	connection_t *c = handle;

	if(!c) {
		logger(DEBUG_ALWAYS, LOG_ERR, "send_meta_sptps() called with NULL pointer!");
		abort();
	}

	buffer_add(&c->outbuf, buffer, length);
	io_set(&c->io, IO_READ | IO_WRITE);

	return true;
}

bool send_meta(connection_t *c, const char *buffer, int length) {
	if(!c) {
		logger(DEBUG_ALWAYS, LOG_ERR, "send_meta() called with NULL pointer!");
		abort();
	}

	logger(DEBUG_META, LOG_DEBUG, "Sending %d bytes of metadata to %s (%s)", length,
			   c->name, c->hostname);

	if(c->protocol_minor >= 2)
		return sptps_send_record(&c->sptps, 0, buffer, length);

	/* Add our data to buffer */
	if(c->status.encryptout) {
		size_t outlen = length;

		if(!cipher_encrypt(c->outcipher, buffer, length, buffer_prepare(&c->outbuf, length), &outlen, false) || outlen != length) {
			logger(DEBUG_ALWAYS, LOG_ERR, "Error while encrypting metadata to %s (%s)",
					c->name, c->hostname);
			return false;
		}
	} else {
		buffer_add(&c->outbuf, buffer, length);
	}

	io_set(&c->io, IO_READ | IO_WRITE);

	return true;
}

void broadcast_meta(connection_t *from, const char *buffer, int length) {
	for list_each(connection_t, c, connection_list)
		if(c != from && c->edge)
			send_meta(c, buffer, length);
}

bool receive_meta_sptps(void *handle, uint8_t type, const void *vdata, uint16_t length) {
	const char *data = vdata;
	connection_t *c = handle;

	if(!c) {
		logger(DEBUG_ALWAYS, LOG_ERR, "receive_meta_sptps() called with NULL pointer!");
		abort();
	}

	if(type == SPTPS_HANDSHAKE) {
		if(c->allow_request == ACK)
			return send_ack(c);
		else
			return true;
	}

	if(!data)
		return true;

	/* Are we receiving a TCPpacket? */

	if(c->tcplen) {
		if(length != c->tcplen)
			return false;
		receive_tcppacket(c, data, length);
		c->tcplen = 0;
		return true;
	}

	/* Change newline to null byte, just like non-SPTPS requests */

	if(data[length - 1] == '\n')
		((char *)data)[length - 1] = 0;

	/* Otherwise we are waiting for a request */

	return receive_request(c, data);
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
		logger(DEBUG_ALWAYS, LOG_ERR, "Input buffer full for %s (%s)", c->name, c->hostname);
		return false;
	}

	inlen = recv(c->socket, inbuf, sizeof inbuf - c->inbuf.len, 0);

	if(inlen <= 0) {
		if(!inlen || !sockerrno) {
			logger(DEBUG_CONNECTIONS, LOG_NOTICE, "Connection closed by %s (%s)",
					   c->name, c->hostname);
		} else if(sockwouldblock(sockerrno))
			return true;
		else
			logger(DEBUG_ALWAYS, LOG_ERR, "Metadata socket read error for %s (%s): %s",
				   c->name, c->hostname, sockstrerror(sockerrno));
		return false;
	}

	do {
		if(c->protocol_minor >= 2)
			return sptps_receive_data(&c->sptps, bufp, inlen);

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

			if(!cipher_decrypt(c->incipher, bufp, inlen, buffer_prepare(&c->inbuf, inlen), &outlen, false) || inlen != outlen) {
				logger(DEBUG_ALWAYS, LOG_ERR, "Error while decrypting metadata from %s (%s)",
					   c->name, c->hostname);
				return false;
			}

			inlen = 0;
		}

		while(c->inbuf.len) {
			/* Are we receiving a TCPpacket? */

			if(c->tcplen) {
				char *tcpbuffer = buffer_read(&c->inbuf, c->tcplen);
				if(!tcpbuffer)
					break;

				if(!c->node) {
					if(c->outgoing && proxytype == PROXY_SOCKS4 && c->allow_request == ID) {
						if(tcpbuffer[0] == 0 && tcpbuffer[1] == 0x5a) {
							logger(DEBUG_CONNECTIONS, LOG_DEBUG, "Proxy request granted");
						} else {
							logger(DEBUG_CONNECTIONS, LOG_ERR, "Proxy request rejected");
							return false;
						}
					} else if(c->outgoing && proxytype == PROXY_SOCKS5 && c->allow_request == ID) {
						if(tcpbuffer[0] != 5) {
							logger(DEBUG_CONNECTIONS, LOG_ERR, "Invalid response from proxy server");
							return false;
						}
						if(tcpbuffer[1] == (char)0xff) {
							logger(DEBUG_CONNECTIONS, LOG_ERR, "Proxy request rejected: unsuitable authentication method");
							return false;
						}
						if(tcpbuffer[2] != 5) {
							logger(DEBUG_CONNECTIONS, LOG_ERR, "Invalid response from proxy server");
							return false;
						}
						if(tcpbuffer[3] == 0) {
							logger(DEBUG_CONNECTIONS, LOG_DEBUG, "Proxy request granted");
						} else {
							logger(DEBUG_CONNECTIONS, LOG_DEBUG, "Proxy request rejected");
							return false;
						}
					} else {
						logger(DEBUG_CONNECTIONS, LOG_ERR, "c->tcplen set but c->node is NULL!");
						abort();
					}
				} else {
					if(c->allow_request == ALL) {
						receive_tcppacket(c, tcpbuffer, c->tcplen);
					} else {
						logger(DEBUG_CONNECTIONS, LOG_ERR, "Got unauthorized TCP packet from %s (%s)", c->name, c->hostname);
						return false;
					}
				}

				c->tcplen = 0;
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
