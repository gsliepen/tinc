/*
    info.c -- Show information about a node, subnet or address
    Copyright (C) 2012-2013 Guus Sliepen <guus@tinc-vpn.org>

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
	fputc('\n', stderr);
}

char *strip_weight(char *netstr) {
	int len = strlen(netstr);
	if(len >= 3 && !strcmp(netstr + len - 3, "#10"))
		netstr[len - 3] = 0;
	return netstr;
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
	union {
		node_status_t bits;
		uint32_t raw;
	} status_union;
	node_status_t status;
	long int last_state_change;

	while(recvline(fd, line, sizeof line)) {
		int n = sscanf(line, "%d %d %s %s port %s %d %d %d %d %x %"PRIx32" %s %s %d %hd %hd %hd %ld", &code, &req, node, host, port, &cipher, &digest, &maclength, &compression, &options, &status_union.raw, nexthop, via, &distance, &pmtu, &minmtu, &maxmtu, &last_state_change);

		if(n == 2)
			break;

		if(n != 18) {
			fprintf(stderr, "Unable to parse node dump from tincd.\n");
			return 1;
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
	printf("Address:      %s port %s\n", host, port);

	char timestr[32] = "never";
	time_t lsc_time = last_state_change;

	if(last_state_change)
		strftime(timestr, sizeof timestr, "%Y-%m-%d %H:%M:%S", localtime(&lsc_time));

	status = status_union.bits;

	if(status.reachable)
		printf("Online since: %s\n", timestr);
	else
		printf("Last seen:    %s\n", timestr);

	printf("Status:      ");
	if(status.validkey)
		printf(" validkey");
	if(status.visited)
		printf(" visited");
	if(status.reachable)
		printf(" reachable");
	if(status.indirect)
		printf(" indirect");
	if(status.sptps)
		printf(" sptps");
	if(status.udp_confirmed)
		printf(" udp_confirmed");
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
	printf("Protocol:     %d.%d\n", PROT_MAJOR, OPTION_VERSION(options));
	printf("Reachability: ");
	if(!strcmp(host, "MYSELF"))
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
		int n = sscanf(line, "%d %d %s %s", &code, &req, from, to);
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
		int n = sscanf(line, "%d %d %s %s", &code, &req, subnet, from);
		if(n == 2)
			break;
		if(n != 4) {
			fprintf(stderr, "Unable to parse subnet dump from tincd.\n");
			return 1;
		}
		if(!strcmp(from, item))
			printf(" %s", strip_weight(subnet));
	}
	printf("\n");

	return 0;
}

static int info_subnet(int fd, const char *item) {
	subnet_t subnet, find;

	if(!str2net(&find, item)) {
		fprintf(stderr, "Could not parse subnet or address '%s'.\n", item);
		return 1;
	}

	bool address = !strchr(item, '/');
	bool weight = strchr(item, '#');
	bool found = false;

	char line[4096];
	char netstr[4096];
	char owner[4096];

	int code, req;

	sendline(fd, "%d %d %s", CONTROL, REQ_DUMP_SUBNETS, item);
	while(recvline(fd, line, sizeof line)) {
		int n = sscanf(line, "%d %d %s %s", &code, &req, netstr, owner);
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
		printf("Subnet: %s\n", strip_weight(netstr));
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
