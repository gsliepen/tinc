/*
    proxy.c -- Proxy handling functions.
    Copyright (C) 2015 Guus Sliepen <guus@tinc-vpn.org>

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

#include "connection.h"
#include "logger.h"
#include "meta.h"
#include "netutl.h"
#include "protocol.h"
#include "proxy.h"
#include "utils.h" //

proxytype_t proxytype;
char *proxyhost;
char *proxyport;
char *proxyuser;
char *proxypass;

static void update_address_ipv4(connection_t *c, void *address, void *port) {
	sockaddrfree(&c->address);
	memset(&c->address, 0, sizeof c->address);
	c->address.sa.sa_family = AF_INET;
	if(address)
		memcpy(&c->address.in.sin_addr, address, sizeof(ipv4_t));
	if(port)
		memcpy(&c->address.in.sin_port, port, sizeof(uint16_t));
	// OpenSSH -D returns all zero address, set it to 0.0.0.1 to prevent spamming ourselves.
	if(!memcmp(&c->address.in.sin_addr, "\0\0\0\0", 4))
		memcpy(&c->address.in.sin_addr, "\0\0\0\01", 4);
}

static void update_address_ipv6(connection_t *c, void *address, void *port) {
	sockaddrfree(&c->address);
	memset(&c->address, 0, sizeof c->address);
	c->address.sa.sa_family = AF_INET6;
	if(address)
		memcpy(&c->address.in6.sin6_addr, address, sizeof(ipv6_t));
	if(port)
		memcpy(&c->address.in6.sin6_port, port, sizeof(uint16_t));
	// OpenSSH -D returns all zero address, set it to 0100:: to prevent spamming ourselves.
	if(!memcmp(&c->address.in6.sin6_addr, "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", 16))
		memcpy(&c->address.in6.sin6_addr, "\01\0\0\0\0\0\0\0", 8);
}

bool send_proxyrequest(connection_t *c) {
	switch(proxytype) {
	case PROXY_SOCKS4:
		if(c->address.sa.sa_family != AF_INET) {
			logger(LOG_ERR, "Can only connect to numeric IPv4 addresses through a SOCKS 4 proxy!");
			return false;
		}
	case PROXY_SOCKS4A: {
		if(c->address.sa.sa_family != AF_INET && c->address.sa.sa_family != AF_UNKNOWN) {
			logger(LOG_ERR, "Can only connect to IPv4 addresses or hostnames through a SOCKS 4a proxy!");
			return false;
		}
		int len = 9;
		if(proxyuser)
			len += strlen(proxyuser);
		if(c->address.sa.sa_family == AF_UNKNOWN)
			len += 1 + strlen(c->address.unknown.address);
		char s4req[len];
		s4req[0] = 4;
		s4req[1] = 1;
		if(c->address.sa.sa_family == AF_INET) {
			memcpy(s4req + 2, &c->address.in.sin_port, 2);
			memcpy(s4req + 4, &c->address.in.sin_addr, 4);
		} else {
			uint16_t port = htons(atoi(c->address.unknown.port));
			memcpy(s4req + 2, &port, 2);
			memcpy(s4req + 4, "\0\0\0\1", 4);
			strcpy(s4req + (9 + (proxyuser ? strlen(proxyuser) : 0)), c->address.unknown.address);
		}
		if(proxyuser)
			strcpy(s4req + 8, proxyuser);
		else
			s4req[8] = 0;
		s4req[sizeof s4req - 1] = 0;
		c->allow_request = PROXY;
		return send_meta(c, s4req, sizeof s4req);
	}

	case PROXY_SOCKS5: {
		int len = 3 + 6;
		if(c->address.sa.sa_family == AF_INET) {
			len += 4;
		} else if(c->address.sa.sa_family == AF_INET6) {
			len += 16;
		} else if(c->address.sa.sa_family == AF_UNKNOWN) {
			len += 1 + strlen(c->address.unknown.address);
		} else {
			logger(LOG_ERR, "Address family %x not supported for SOCKS 5 proxies!", c->address.sa.sa_family);
			return false;
		}
		if(proxypass)
			len += 3 + strlen(proxyuser) + strlen(proxypass);
		char s5req[len];
		int i = 0;
		s5req[i++] = 5;
		s5req[i++] = 1;
		if(proxypass) {
			s5req[i++] = 2;
			s5req[i++] = 1;
			s5req[i++] = strlen(proxyuser);
			strcpy(s5req + i, proxyuser);
			i += strlen(proxyuser);
			s5req[i++] = strlen(proxypass);
			strcpy(s5req + i, proxypass);
			i += strlen(proxypass);
		} else {
			s5req[i++] = 0;
		}
		s5req[i++] = 5;
		s5req[i++] = 1;
		s5req[i++] = 0;
		if(c->address.sa.sa_family == AF_INET) {
			s5req[i++] = 1;
			memcpy(s5req + i, &c->address.in.sin_addr, 4);
			i += 4;
			memcpy(s5req + i, &c->address.in.sin_port, 2);
			i += 2;
		} else if(c->address.sa.sa_family == AF_INET6) {
			s5req[i++] = 4;
			memcpy(s5req + i, &c->address.in6.sin6_addr, 16);
			i += 16;
			memcpy(s5req + i, &c->address.in6.sin6_port, 2);
			i += 2;
		} else if(c->address.sa.sa_family == AF_UNKNOWN) {
			s5req[i++] = 3;
			int len = strlen(c->address.unknown.address);
			s5req[i++] = len;
			memcpy(s5req + i, c->address.unknown.address, len);
			i += len;
			uint16_t port = htons(atoi(c->address.unknown.port));
			memcpy(s5req + i, &port, 2);
			i += 2;
		} else {
			logger(LOG_ERR, "Unknown address family while trying to connect to SOCKS5 proxy");
			return false;
		}
		if(i > len)
			abort();
		c->allow_request = PROXY;
		return send_meta(c, s5req, sizeof s5req);
	}

	case PROXY_HTTP: {
		char *host;
		char *port;

		sockaddr2str(&c->address, &host, &port);
		send_request(c, "CONNECT %s:%s HTTP/1.1\r\n\r", host, port);
		free(host);
		free(port);
		c->allow_request = PROXY;
		return true;
	}

	case PROXY_EXEC:
		return true;

	default:
		logger(LOG_ERR, "Unknown proxy type");
		return false;
	}
}

int receive_proxy_meta(connection_t *c, int start, int lenin) {
	switch(proxytype) {
	case PROXY_SOCKS4:
	case PROXY_SOCKS4A:
		if(c->buflen < 8)
			return 0;
		if(c->buffer[0] == 0 && c->buffer[1] == 0x5a) {
			if(c->address.sa.sa_family == AF_UNKNOWN)
				update_address_ipv4(c, c->buffer + 4, c->buffer + 2);

			ifdebug(CONNECTIONS) logger(LOG_DEBUG, "Proxy request granted");
			c->allow_request = ID;
			return 8;
		} else {
			logger(LOG_ERR, "Proxy request rejected");
			return -1;
		}

	case PROXY_SOCKS5:
		if(c->buflen < 2)
			return 0;
		if(c->buffer[0] != 0x05 || c->buffer[1] == (char)0xff) {
			logger(LOG_ERR, "Proxy authentication method rejected");
			return -1;
		}
		int offset = 2;
		if(c->buffer[1] == 0x02) {
			if(c->buflen < 4)
				return 0;
			if(c->buffer[2] != 0x05 || c->buffer[3] != 0x00) {
				logger(LOG_ERR, "Proxy username/password rejected");
				return -1;
			}
			offset += 2;
		}
		if(c->buflen - offset < 7)
			return 0;
		if(c->buffer[offset] != 0x05  || c->buffer[offset + 1] != 0x00) {
			logger(LOG_ERR, "Proxy request rejected");
			return -1;
		}
		int replen = offset + 6;
		switch(c->buffer[offset + 3]) {
			case 0x01: // IPv4
				if(c->address.sa.sa_family == AF_UNKNOWN)
					update_address_ipv4(c, c->buffer + offset + 4, c->buffer + offset + 8);
				replen += 4;
				break;
			case 0x03: // Hostname
				if(c->address.sa.sa_family == AF_UNKNOWN)
					update_address_ipv4(c, "\0\0\0\1", "\0\0");
				replen += ((uint8_t *)c->buffer)[offset + 4];
				break;
			case 0x04: // IPv6
				if(c->address.sa.sa_family == AF_UNKNOWN)
					update_address_ipv6(c, c->buffer + offset + 4, c->buffer + offset + 20);
				replen += 16;
				break;
			default:
				logger(LOG_ERR, "Proxy reply malformed");
				return -1;
		}
		if(c->buflen < replen) {
			return 0;
		} else {
			ifdebug(CONNECTIONS) logger(LOG_DEBUG, "Proxy request granted");
			c->allow_request = ID;
			return replen;
		}

	case PROXY_HTTP: {
		char *p = memchr(c->buffer, '\n', c->buflen);
		if(!p || p - c->buffer >= c->buflen)
			return 0;
		p = memchr(p + 1, '\n', c->buflen - (p + 1 - c->buffer));
		if(!p)
			return 0;

		if(c->buflen < 9)
			return 0;

		if(!strncasecmp(c->buffer, "HTTP/1.1 ", 9)) {
			if(!strncmp(c->buffer + 9, "200", 3)) {
				if(c->address.sa.sa_family == AF_UNKNOWN)
					update_address_ipv4(c, "\0\0\0\1", "\0\0");
				logger(LOG_DEBUG, "Proxy request granted");
				replen = p  + 1 - c->buffer;
				c->allow_request = ID;
				return replen;
			} else {
				logger(LOG_ERR, "Proxy request rejected: %s", c->buffer + 9);
				return false;
			}
		} else {
			logger(LOG_ERR, "Proxy reply malformed");
			return -1;
		}
	}

	default:
		abort();
	}
}
