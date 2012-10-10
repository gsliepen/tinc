/*
    subnet_parse.c -- handle subnet parsing
    Copyright (C) 2000-2012 Guus Sliepen <guus@tinc-vpn.org>,
                  2000-2005 Ivo Timmermans

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

#include "logger.h"
#include "net.h"
#include "netutl.h"
#include "subnet.h"
#include "utils.h"
#include "xalloc.h"

/* Subnet mask handling */

int maskcmp(const void *va, const void *vb, int masklen) {
	int i, m, result;
	const char *a = va;
	const char *b = vb;

	for(m = masklen, i = 0; m >= 8; m -= 8, i++) {
		result = a[i] - b[i];
		if(result)
			return result;
	}

	if(m)
		return (a[i] & (0x100 - (1 << (8 - m)))) -
			(b[i] & (0x100 - (1 << (8 - m))));

	return 0;
}

void mask(void *va, int masklen, int len) {
	int i;
	char *a = va;

	i = masklen / 8;
	masklen %= 8;

	if(masklen)
		a[i++] &= (0x100 - (1 << (8 - masklen)));

	for(; i < len; i++)
		a[i] = 0;
}

void maskcpy(void *va, const void *vb, int masklen, int len) {
	int i, m;
	char *a = va;
	const char *b = vb;

	for(m = masklen, i = 0; m >= 8; m -= 8, i++)
		a[i] = b[i];

	if(m) {
		a[i] = b[i] & (0x100 - (1 << (8 - m)));
		i++;
	}

	for(; i < len; i++)
		a[i] = 0;
}

bool maskcheck(const void *va, int masklen, int len) {
	int i;
	const char *a = va;

	i = masklen / 8;
	masklen %= 8;

	if(masklen && a[i++] & (0xff >> masklen))
		return false;

	for(; i < len; i++)
		if(a[i] != 0)
			return false;

	return true;
}

/* Subnet comparison */

static int subnet_compare_mac(const subnet_t *a, const subnet_t *b) {
	int result;

	result = memcmp(&a->net.mac.address, &b->net.mac.address, sizeof a->net.mac.address);

	if(result)
		return result;

	result = a->weight - b->weight;

	if(result || !a->owner || !b->owner)
		return result;

	return strcmp(a->owner->name, b->owner->name);
}

static int subnet_compare_ipv4(const subnet_t *a, const subnet_t *b) {
	int result;

	result = b->net.ipv4.prefixlength - a->net.ipv4.prefixlength;

	if(result)
		return result;

	result = memcmp(&a->net.ipv4.address, &b->net.ipv4.address, sizeof(ipv4_t));

	if(result)
		return result;

	result = a->weight - b->weight;

	if(result || !a->owner || !b->owner)
		return result;

	return strcmp(a->owner->name, b->owner->name);
}

static int subnet_compare_ipv6(const subnet_t *a, const subnet_t *b) {
	int result;

	result = b->net.ipv6.prefixlength - a->net.ipv6.prefixlength;

	if(result)
		return result;

	result = memcmp(&a->net.ipv6.address, &b->net.ipv6.address, sizeof(ipv6_t));

	if(result)
		return result;

	result = a->weight - b->weight;

	if(result || !a->owner || !b->owner)
		return result;

	return strcmp(a->owner->name, b->owner->name);
}

int subnet_compare(const subnet_t *a, const subnet_t *b) {
	int result;

	result = a->type - b->type;

	if(result)
		return result;

	switch (a->type) {
	case SUBNET_MAC:
		return subnet_compare_mac(a, b);
	case SUBNET_IPV4:
		return subnet_compare_ipv4(a, b);
	case SUBNET_IPV6:
		return subnet_compare_ipv6(a, b);
	default:
		logger(DEBUG_ALWAYS, LOG_ERR, "subnet_compare() was called with unknown subnet type %d, exitting!", a->type);
		exit(1);
	}

	return 0;
}

/* Ascii representation of subnets */

bool str2net(subnet_t *subnet, const char *subnetstr) {
	int i, l;
	uint16_t x[8];
	int weight = 10;

	if(sscanf(subnetstr, "%hu.%hu.%hu.%hu/%d#%d",
			  &x[0], &x[1], &x[2], &x[3], &l, &weight) >= 5) {
		if(l < 0 || l > 32)
			return false;

		subnet->type = SUBNET_IPV4;
		subnet->net.ipv4.prefixlength = l;
		subnet->weight = weight;

		for(int i = 0; i < 4; i++) {
			if(x[i] > 255)
				return false;
			subnet->net.ipv4.address.x[i] = x[i];
		}

		return true;
	}

	if(sscanf(subnetstr, "%hx:%hx:%hx:%hx:%hx:%hx:%hx:%hx/%d#%d",
			  &x[0], &x[1], &x[2], &x[3], &x[4], &x[5], &x[6], &x[7],
			  &l, &weight) >= 9) {
		if(l < 0 || l > 128)
			return false;

		subnet->type = SUBNET_IPV6;
		subnet->net.ipv6.prefixlength = l;
		subnet->weight = weight;

		for(i = 0; i < 8; i++)
			subnet->net.ipv6.address.x[i] = htons(x[i]);

		return true;
	}

	if(sscanf(subnetstr, "%hu.%hu.%hu.%hu#%d", &x[0], &x[1], &x[2], &x[3], &weight) >= 4) {
		subnet->type = SUBNET_IPV4;
		subnet->net.ipv4.prefixlength = 32;
		subnet->weight = weight;

		for(i = 0; i < 4; i++) {
			if(x[i] > 255)
				return false;
			subnet->net.ipv4.address.x[i] = x[i];
		}

		return true;
	}

	if(sscanf(subnetstr, "%hx:%hx:%hx:%hx:%hx:%hx:%hx:%hx#%d",
			  &x[0], &x[1], &x[2], &x[3], &x[4], &x[5], &x[6], &x[7], &weight) >= 8) {
		subnet->type = SUBNET_IPV6;
		subnet->net.ipv6.prefixlength = 128;
		subnet->weight = weight;

		for(i = 0; i < 8; i++)
			subnet->net.ipv6.address.x[i] = htons(x[i]);

		return true;
	}

	if(sscanf(subnetstr, "%hx:%hx:%hx:%hx:%hx:%hx#%d",
			  &x[0], &x[1], &x[2], &x[3], &x[4], &x[5], &weight) >= 6) {
		subnet->type = SUBNET_MAC;
		subnet->weight = weight;

		for(i = 0; i < 6; i++)
			subnet->net.mac.address.x[i] = x[i];

		return true;
	}

	// IPv6 short form
	if(strstr(subnetstr, "::")) {
		const char *p;
		char *q;
		int colons = 0;

		// Count number of colons
		for(p = subnetstr; *p; p++)
			if(*p == ':')
				colons++;

		if(colons > 7)
			return false;

		// Scan numbers before the double colon
		p = subnetstr;
		for(i = 0; i < colons; i++) {
			if(*p == ':')
				break;
			x[i] = strtoul(p, &q, 0x10);
			if(!q || p == q || *q != ':')
				return false;
			p = ++q;
		}

		p++;
		colons -= i;
		if(!i) {
			p++;
			colons--;
		}

		if(!*p || *p == '/' || *p == '#')
			colons--;

		// Fill in the blanks
		for(; i < 8 - colons; i++)
			x[i] = 0;

		// Scan the remaining numbers
		for(; i < 8; i++) {
			x[i] = strtoul(p, &q, 0x10);
			if(!q || p == q)
				return false;
			if(i == 7) {
				p = q;
				break;
			}
			if(*q != ':')
				return false;
			p = ++q;
		}

		l = 128;
		if(*p == '/')
			sscanf(p, "/%d#%d", &l, &weight);
		else if(*p == '#')
			sscanf(p, "#%d", &weight);

		if(l < 0 || l > 128)
			return false;

		subnet->type = SUBNET_IPV6;
		subnet->net.ipv6.prefixlength = l;
		subnet->weight = weight;

		for(i = 0; i < 8; i++)
			subnet->net.ipv6.address.x[i] = htons(x[i]);

		return true;
	}

	return false;
}

bool net2str(char *netstr, int len, const subnet_t *subnet) {
	if(!netstr || !subnet) {
		logger(DEBUG_ALWAYS, LOG_ERR, "net2str() was called with netstr=%p, subnet=%p!", netstr, subnet);
		return false;
	}

	switch (subnet->type) {
		case SUBNET_MAC:
			snprintf(netstr, len, "%hx:%hx:%hx:%hx:%hx:%hx#%d",
					 subnet->net.mac.address.x[0],
					 subnet->net.mac.address.x[1],
					 subnet->net.mac.address.x[2],
					 subnet->net.mac.address.x[3],
					 subnet->net.mac.address.x[4],
					 subnet->net.mac.address.x[5],
					 subnet->weight);
			break;

		case SUBNET_IPV4:
			snprintf(netstr, len, "%hu.%hu.%hu.%hu/%d#%d",
					 subnet->net.ipv4.address.x[0],
					 subnet->net.ipv4.address.x[1],
					 subnet->net.ipv4.address.x[2],
					 subnet->net.ipv4.address.x[3],
					 subnet->net.ipv4.prefixlength,
					 subnet->weight);
			break;

		case SUBNET_IPV6:
			snprintf(netstr, len, "%hx:%hx:%hx:%hx:%hx:%hx:%hx:%hx/%d#%d",
					 ntohs(subnet->net.ipv6.address.x[0]),
					 ntohs(subnet->net.ipv6.address.x[1]),
					 ntohs(subnet->net.ipv6.address.x[2]),
					 ntohs(subnet->net.ipv6.address.x[3]),
					 ntohs(subnet->net.ipv6.address.x[4]),
					 ntohs(subnet->net.ipv6.address.x[5]),
					 ntohs(subnet->net.ipv6.address.x[6]),
					 ntohs(subnet->net.ipv6.address.x[7]),
					 subnet->net.ipv6.prefixlength,
					 subnet->weight);
			break;

		default:
			logger(DEBUG_ALWAYS, LOG_ERR, "net2str() was called with unknown subnet type %d, exiting!", subnet->type);
			exit(1);
	}

	return true;
}
