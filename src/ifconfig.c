/*
    ifconfig.c -- Generate platform specific interface configuration commands
    Copyright (C) 2016-2017 Guus Sliepen <guus@tinc-vpn.org>

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
	fprintf(out, "netsh interface ipv4 set address \"%%INTERFACE%%\" dhcp\n");
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
	subnet_t address = {};
	char address_str[MAXNETSTR];
	if(!str2net(&address, value) || !net2str(address_str, sizeof address_str, &address)) {
		fprintf(stderr, "Could not parse address in Ifconfig statement\n");
		return;
	}
	switch(address.type) {
		case SUBNET_IPV4: ipv4 = address; break;
		case SUBNET_IPV6: ipv6 = address; break;
		default: return;
	}
#if defined(HAVE_LINUX)
	switch(address.type) {
		case SUBNET_MAC:  fprintf(out, "ip link set \"$INTERFACE\" address %s\n", address_str); break;
		case SUBNET_IPV4: fprintf(out, "ip addr replace %s dev \"$INTERFACE\"\n", address_str); break;
		case SUBNET_IPV6: fprintf(out, "ip addr replace %s dev \"$INTERFACE\"\n", address_str); break;
		default: return;
	}
#elif defined(HAVE_MINGW) || defined(HAVE_CYGWIN)
	switch(address.type) {
		case SUBNET_MAC:  fprintf(out, "ip link set \"$INTERFACE\" address %s\n", address_str); break;
		case SUBNET_IPV4: fprintf(out, "netsh inetface ipv4 set address \"$INTERFACE\" static %s\n", address_str); break;
		case SUBNET_IPV6: fprintf(out, "netsh inetface ipv6 set address \"$INTERFACE\" static %s\n", address_str); break;
		default: return;
	}
#else // assume BSD
	switch(address.type) {
		case SUBNET_MAC:  fprintf(out, "ifconfig \"$INTERFACE\" link %s\n", address_str); break;
		case SUBNET_IPV4: fprintf(out, "ifconfig \"$INTERFACE\" %s\n", address_str); break;
		case SUBNET_IPV6: fprintf(out, "ifconfig \"$INTERFACE\" inet6 %s\n", address_str); break;
		default: return;
	}
#endif
}

void ifconfig_route(FILE *out, const char *value) {
	subnet_t subnet = {}, gateway = {};
	char subnet_str[MAXNETSTR] = "", gateway_str[MAXNETSTR] = "";
	char *sep = strchr(value, ' ');
	if(sep)
		*sep++ = 0;
	if(!str2net(&subnet, value) || !net2str(subnet_str, sizeof subnet_str, &subnet) || subnet.type == SUBNET_MAC) {
		fprintf(stderr, "Could not parse subnet in Route statement\n");
		return;
	}
	if(sep) {
		if(!str2net(&gateway, sep) || !net2str(gateway_str, sizeof gateway_str, &gateway) || gateway.type != subnet.type) {
			fprintf(stderr, "Could not parse gateway in Route statement\n");
			return;
		}
		char *slash = strchr(gateway_str, '/'); if(slash) *slash = 0;
	}
#if defined(HAVE_LINUX)
	if(*gateway_str) {
		switch(subnet.type) {
			case SUBNET_IPV4: fprintf(out, "ip route add %s via %s dev \"$INTERFACE\"\n", subnet_str, gateway_str); break;
			case SUBNET_IPV6: fprintf(out, "ip route add %s via %s dev \"$INTERFACE\"\n", subnet_str, gateway_str); break;
			default: return;
		}
	} else {
		switch(subnet.type) {
			case SUBNET_IPV4: fprintf(out, "ip route add %s dev \"$INTERFACE\"\n", subnet_str); break;
			case SUBNET_IPV6: fprintf(out, "ip route add %s dev \"$INTERFACE\"\n", subnet_str); break;
			default: return;
		}
	}
#elif defined(HAVE_MINGW) || defined(HAVE_CYGWIN)
	if(*gateway_str) {
		switch(subnet.type) {
			case SUBNET_IPV4: fprintf(out, "netsh inetface ipv4 add route %s \"%%INTERFACE%%\" %s\n", subnet_str, gateway_str); break;
			case SUBNET_IPV6: fprintf(out, "netsh inetface ipv6 add route %s \"%%INTERFACE%%\" %s\n", subnet_str, gateway_str); break;
			default: return;
		}
	} else {
		switch(subnet.type) {
			case SUBNET_IPV4: fprintf(out, "netsh inetface ipv4 add route %s \"%%INTERFACE%%\"\n", subnet_str); break;
			case SUBNET_IPV6: fprintf(out, "netsh inetface ipv6 add route %s \"%%INTERFACE%%\"\n", subnet_str); break;
			default: return;
		}
	}
#else // assume BSD
	if(!*gateway_str) {
		switch(subnet.type) {
			case SUBNET_IPV4:
				if(!ipv4.type) {
					fprintf(stderr, "Route requested but no Ifconfig\n");
					return;
				}
				net2str(gateway_str, sizeof gateway_str, &ipv4);
				break;
			case SUBNET_IPV6:
				if(!ipv6.type) {
					fprintf(stderr, "Route requested but no Ifconfig\n");
					return;
				}
				net2str(gateway_str, sizeof gateway_str, &ipv6);
				break;
			default: return;
		}
		char *slash = strchr(gateway_str, '/'); if(slash) *slash = 0;
	}

	switch(subnet.type) {
		case SUBNET_IPV4: fprintf(out, "route add %s %s\n", subnet_str, gateway_str); break;
		case SUBNET_IPV6: fprintf(out, "route add -inet6 %s %s\n", subnet_str, gateway_str); break;
		default: return;
	}
#endif
}
