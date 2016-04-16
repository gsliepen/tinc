/*
    ifconfig.c -- Generate platform specific interface configuration commands
    Copyright (C) 2016 Guus Sliepen <guus@tinc-vpn.org>

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

#include "conf.h"
#include "ifconfig.h"
#include "subnet.h"

static long start;

#ifndef HAVE_MINGW
void ifconfig_header(FILE *out) {
	fprintf(out, "#!/bin/sh\n");
	start = ftell(out);
}

void ifconfig_dhcp(FILE *out) {
	fprintf(out, "dhclient -nw \"$INTERFACE\"\n");
}

void ifconfig_dhcp6(FILE *out) {
	fprintf(out, "dhclient -6 -nw \"$INTERFACE\"\n");
}

void ifconfig_slaac(FILE *out) {
#ifdef HAVE_LINUX
	fprintf(out, "echo 1 >\"/proc/sys/net/ipv6/conf/$INTERFACE/accept_ra\"\n");
	fprintf(out, "echo 1 >\"/proc/sys/net/ipv6/conf/$INTERFACE/autoconf\"\n");
#else
	fprintf(out, "rtsol \"$INTERFACE\" &\n");
#endif
}

bool ifconfig_footer(FILE *out) {
	if(ftell(out) == start) {
		fprintf(out, "echo 'Unconfigured tinc-up script, please edit '$0'!'\n\n#ifconfig $INTERFACE <your vpn IP address> netmask <netmask of whole VPN>\n");
		return false;
	} else {
#ifdef HAVE_LINUX
		fprintf(out, "ip link set \"$INTERFACE\" up\n");
#else
		fprintf(out, "ifconfig \"$INTERFACE\" up\n");
#endif
		return true;
	}
}
#else
void ifconfig_header(FILE *out) {
	start = ftell(out);
}

void ifconfig_dhcp(FILE *out) {
	fprintf(out, "netsh interface ipv4 set address \"%INTERFACE%\" dhcp\n");
}

void ifconfig_dhcp6(FILE *out) {
	fprintf(stderr, "DHCPv6 requested, but not supported by tinc on this platform\n");
}

void ifconfig_slaac(FILE *out) {
	// It's the default?
}

bool ifconfig_footer(FILE *out) {
	return ftell(out) != start;
}
#endif

static subnet_t ipv4, ipv6;

void ifconfig_address(FILE *out, const char *value) {
	subnet_t subnet = {};
	char str[MAXNETSTR];
	if(!str2net(&subnet, value) || !net2str(str, sizeof str, &subnet)) {
		fprintf(stderr, "Could not parse Ifconfig statement\n");
		return;
	}
	switch(subnet.type) {
		case SUBNET_IPV4: ipv4 = subnet; break;
		case SUBNET_IPV6: ipv6 = subnet; break;
	}
#if defined(HAVE_LINUX)
	switch(subnet.type) {
		case SUBNET_MAC:  fprintf(out, "ip link set \"$INTERFACE\" address %s\n", str); break;
		case SUBNET_IPV4: fprintf(out, "ip addr replace %s dev \"$INTERFACE\"\n", str); break;
		case SUBNET_IPV6: fprintf(out, "ip addr replace %s dev \"$INTERFACE\"\n", str); break;
	}
#elif defined(HAVE_BSD)
	switch(subnet.type) {
		case SUBNET_MAC:  fprintf(out, "ifconfig \"$INTERFACE\" link %s\n", str); break;
		case SUBNET_IPV4: fprintf(out, "ifconfig \"$INTERFACE\" %s\n", str); break;
		case SUBNET_IPV6: fprintf(out, "ifconfig \"$INTERFACE\" inet6 %s\n", str); break;
	}
#elif defined(HAVE_MINGW) || defined(HAVE_CYGWIN)
	switch(subnet.type) {
		case SUBNET_MAC:  fprintf(out, "ip link set \"$INTERFACE\" address %s\n", str); break;
		case SUBNET_IPV4: fprintf(out, "netsh inetface ipv4 set address \"$INTERFACE\" static %s\n", str); break;
		case SUBNET_IPV6: fprintf(out, "netsh inetface ipv6 set address \"$INTERFACE\" static %s\n", str); break;
	}
#endif
}

void ifconfig_route(FILE *out, const char *value) {
	subnet_t subnet = {};
	char str[MAXNETSTR];
	if(!str2net(&subnet, value) || !net2str(str, sizeof str, &subnet) || subnet.type == SUBNET_MAC) {
		fprintf(stderr, "Could not parse Ifconfig statement\n");
		return;
	}
#if defined(HAVE_LINUX)
	switch(subnet.type) {
		case SUBNET_IPV4: fprintf(out, "ip route add %s dev \"$INTERFACE\"\n", str); break;
		case SUBNET_IPV6: fprintf(out, "ip route add %s dev \"$INTERFACE\"\n", str); break;
	}
#elif defined(HAVE_BSD)
	// BSD route command is silly and doesn't accept an interface name as a destination.
	char gwstr[MAXNETSTR] = "";
	switch(subnet.type) {
		case SUBNET_IPV4:
			if(!ipv4.type) {
				fprintf(stderr, "Route requested but no Ifconfig\n");
				return;
			}
			net2str(gwstr, sizeof gwstr, &ipv4);
			char *p = strchr(gwstr, '/'); if(p) *p = 0;
			fprintf(out, "route add %s %s\n", str, gwstr);
			break;
		case SUBNET_IPV6:
			if(!ipv6.type) {
				fprintf(stderr, "Route requested but no Ifconfig\n");
				return;
			}
			net2str(gwstr, sizeof gwstr, &ipv6);
			char *p = strchr(gwstr, '/'); if(p) *p = 0;
			fprintf(out, "route add -inet6 %s %s\n", str, gwstr);
			break;
	}
#elif defined(HAVE_MINGW) || defined(HAVE_CYGWIN)
	switch(subnet.type) {
		case SUBNET_IPV4: fprintf(out, "netsh inetface ipv4 add route %s \"$INTERFACE\"\n", str); break;
		case SUBNET_IPV6: fprintf(out, "netsh inetface ipv6 add route %s \"$INTERFACE\"\n", str); break;
	}
#endif
}
