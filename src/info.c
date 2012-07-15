/*
    info.c -- Show information about a node, subnet or address
    Copyright (C) 2012 Guus Sliepen <guus@tinc-vpn.org>

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

#include "control_common.h"
#include "list.h"
#include "subnet.h"
#include "tincctl.h"
#include "info.h"
#include "xalloc.h"

void logger(int level, int priority, const char *format, ...) {
	va_list ap;
        va_start(ap, format);
        vfprintf(stderr, format, ap);
        va_end(ap);
}

static int info_node(int fd, const char *item) {
	// Check the list of nodes
	sendline(fd, "%d %d %s", CONTROL, REQ_DUMP_NODES, item);

	bool found = false;
	char line[4096];

	char node[4096];
	char from[4096];
	char to[4096];
	char subnet[4096];
	char host[4096];
	char port[4096];
	char via[4096];
	char nexthop[4096];
	int code, req, cipher, digest, maclength, compression, distance;
       	short int pmtu, minmtu, maxmtu;
	unsigned int options;
	node_status_t status;

	while(recvline(fd, line, sizeof line)) {
		int n = sscanf(line, "%d %d %s at %s port %s cipher %d digest %d maclength %d compression %d options %x status %04x nexthop %s via %s distance %d pmtu %hd (min %hd max %hd)", &code, &req, node, host, port, &cipher, &digest, &maclength, &compression, &options, (unsigned *)&status, nexthop, via, &distance, &pmtu, &minmtu, &maxmtu);

		if(n == 2)
			break;

		if(n != 17) {
			*port = 0;
			n = sscanf(line, "%d %d %s at %s cipher %d digest %d maclength %d compression %d options %x status %04x nexthop %s via %s distance %d pmtu %hd (min %hd max %hd)", &code, &req, node, host, &cipher, &digest, &maclength, &compression, &options, (unsigned *)&status, nexthop, via, &distance, &pmtu, &minmtu, &maxmtu);

			if(n != 16) {
				fprintf(stderr, "Unable to parse node dump from tincd.\n");
				return 1;
			}
		}

		if(!strcmp(node, item)) {
			found = true;
			break;
		}
	}

	if(!found) {
		fprintf(stderr, "Unknown node %s.\n", item);
		return 1;
	}

	while(recvline(fd, line, sizeof line)) {
		if(sscanf(line, "%d %d %s", &code, &req, node) == 2)
			break;
	}
	
	printf("Node:         %s\n", item);
	if(*port)
		printf("Address:      %s port %s\n", host, port);
	printf("Status:      ");
	if(status.validkey)
		printf(" validkey");
	if(status.visited)
		printf(" visited");
	if(status.reachable)
		printf(" reachable");
	if(status.indirect)
		printf(" indirect");
	if(status.ecdh)
		printf(" ecdh");
	printf("\n");
	printf("Options:     ");
	if(options & OPTION_INDIRECT)
		printf(" indirect");
	if(options & OPTION_TCPONLY)
		printf(" tcponly");
	if(options & OPTION_PMTU_DISCOVERY)
		printf(" pmtu_discovery");
	if(options & OPTION_CLAMP_MSS)
		printf(" clamp_mss");
	printf("\n");
	printf("Reachability: ");
	if(!*port)
		printf("can reach itself\n");
	else if(!status.reachable)
		printf("unreachable\n");
	else if(strcmp(via, item))
		printf("indirectly via %s\n", via);
	else if(!status.validkey)
		printf("unknown\n");
	else if(minmtu > 0)
		printf("directly with UDP\nPMTU:         %d\n", pmtu);
	else if(!strcmp(nexthop, item))
		printf("directly with TCP\n");
	else
		printf("none, forwarded via %s\n", nexthop);

	// List edges
	printf("Edges:       ");
	sendline(fd, "%d %d %s", CONTROL, REQ_DUMP_EDGES, item);
	while(recvline(fd, line, sizeof line)) {
		int n = sscanf(line, "%d %d %s to %s", &code, &req, from, to);
		if(n == 2)
			break;
		if(n != 4) {
			fprintf(stderr, "Unable to parse edge dump from tincd.\n%s\n", line);
			return 1;
		}
		if(!strcmp(from, item))
			printf(" %s", to);
	}
	printf("\n");

	// List subnets
	printf("Subnets:     ");
	sendline(fd, "%d %d %s", CONTROL, REQ_DUMP_SUBNETS, item);
	while(recvline(fd, line, sizeof line)) {
		int n = sscanf(line, "%d %d %s owner %s", &code, &req, subnet, from);
		if(n == 2)
			break;
		if(n != 4) {
			fprintf(stderr, "Unable to parse subnet dump from tincd.\n");
			return 1;
		}
		if(!strcmp(from, item))
			printf(" %s", subnet);
	}
	printf("\n");

	return 0;
}

static int info_subnet(int fd, const char *item) {
	subnet_t subnet, find;

	if(!str2net(&find, item))
		return 1;

	bool address = !strchr(item, '/');
	bool weight = strchr(item, '#');
	bool found = false;

	char line[4096];
	char netstr[4096];
	char owner[4096];

	int code, req;

	sendline(fd, "%d %d %s", CONTROL, REQ_DUMP_SUBNETS, item);
	while(recvline(fd, line, sizeof line)) {
		int n = sscanf(line, "%d %d %s owner %s", &code, &req, netstr, owner);
		if(n == 2)
			break;

		if(n != 4 || !str2net(&subnet, netstr)) {
			fprintf(stderr, "Unable to parse subnet dump from tincd.\n");
			return 1;
		}

		if(find.type != subnet.type)
			continue;

		if(weight) {
			if(find.weight != subnet.weight)
				continue;
		}

		if(find.type == SUBNET_IPV4) {
			if(address) {
				if(maskcmp(&find.net.ipv4.address, &subnet.net.ipv4.address, subnet.net.ipv4.prefixlength))
					continue;
			} else {
				if(find.net.ipv4.prefixlength != subnet.net.ipv4.prefixlength)
					continue;
				if(memcmp(&find.net.ipv4.address, &subnet.net.ipv4.address, sizeof subnet.net.ipv4))
					continue;
			}
		} else if(find.type == SUBNET_IPV6) {
			if(address) {
				if(maskcmp(&find.net.ipv6.address, &subnet.net.ipv6.address, subnet.net.ipv6.prefixlength))
					continue;
			} else {
				if(find.net.ipv6.prefixlength != subnet.net.ipv6.prefixlength)
					continue;
				if(memcmp(&find.net.ipv6.address, &subnet.net.ipv6.address, sizeof subnet.net.ipv6))
					continue;
			}
		} if(find.type == SUBNET_MAC) {
			if(memcmp(&find.net.mac.address, &subnet.net.mac.address, sizeof subnet.net.mac))
				continue;
		}

		found = true;
		printf("Subnet: %s\n", netstr);
		printf("Owner:  %s\n", owner);
	}

	if(!found) {
		if(address)
			fprintf(stderr, "Unknown address %s.\n", item);
		else
			fprintf(stderr, "Unknown subnet %s.\n", item);
		return 1;
	}

	return 0;
}

int info(int fd, const char *item) {
	if(check_id(item))
		return info_node(fd, item);
	if(strchr(item, '.') || strchr(item, ':'))
		return info_subnet(fd, item);

	fprintf(stderr, "Argument is not a node name, subnet or address.\n");
	return 1;
}
