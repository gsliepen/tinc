/*
    upnp.c -- UPnP-IGD client
    Copyright (C) 2015-2018 Guus Sliepen <guus@tinc-vpn.org>,

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

#include "upnp.h"

#ifndef HAVE_MINGW
#include <pthread.h>
#endif

#include "miniupnpc/miniupnpc.h"
#include "miniupnpc/upnpcommands.h"
#include "miniupnpc/upnperrors.h"

#include "system.h"
#include "logger.h"
#include "names.h"
#include "net.h"
#include "netutl.h"
#include "utils.h"

static bool upnp_tcp;
static bool upnp_udp;
static int upnp_discover_wait = 5;
static int upnp_refresh_period = 60;

// Unfortunately, libminiupnpc devs don't seem to care about API compatibility,
// and there are slight changes to function signatures between library versions.
// Well, at least they publish a "MINIUPNPC_API_VERSION" constant, so we got that going for us, which is nice.
// Differences between API versions are documented in "apiversions.txt" in the libminiupnpc distribution.

#ifndef MINIUPNPC_API_VERSION
#define MINIUPNPC_API_VERSION 0
#endif

static struct UPNPDev *upnp_discover(int delay, int *error) {
#if MINIUPNPC_API_VERSION <= 13

#if MINIUPNPC_API_VERSION < 8
#warning "The version of libminiupnpc you're building against seems to be too old. Expect trouble."
#endif

	return upnpDiscover(delay, NULL, NULL, false, false, error);

#elif MINIUPNPC_API_VERSION <= 14

	return upnpDiscover(delay, NULL, NULL, false, false, 2, error);

#else

#if MINIUPNPC_API_VERSION > 17
#warning "The version of libminiupnpc you're building against seems to be too recent. Expect trouble."
#endif

	return upnpDiscover(delay, NULL, NULL, UPNP_LOCAL_PORT_ANY, false, 2, error);

#endif
}

static void upnp_add_mapping(struct UPNPUrls *urls, struct IGDdatas *data, const char *myaddr, int socket, const char *proto) {
	// Extract the port from the listening socket.
	// Note that we can't simply use listen_socket[].sa because this won't have the port
	// if we're running with Port=0 (dynamically assigned port).
	sockaddr_t sa;
	socklen_t salen = sizeof(sa);

	if(getsockname(socket, &sa.sa, &salen)) {
		logger(DEBUG_PROTOCOL, LOG_ERR, "[upnp] Unable to get socket address: [%d] %s", sockerrno, sockstrerror(sockerrno));
		return;
	}

	char *port;
	sockaddr2str(&sa, NULL, &port);

	if(!port) {
		logger(DEBUG_PROTOCOL, LOG_ERR, "[upnp] Unable to get socket port");
		return;
	}

	// Use a lease twice as long as the refresh period so that the mapping won't expire before we refresh.
	char lease_duration[16];
	snprintf(lease_duration, sizeof(lease_duration), "%d", upnp_refresh_period * 2);

	int error = UPNP_AddPortMapping(urls->controlURL, data->first.servicetype, port, port, myaddr, identname, proto, NULL, lease_duration);

	if(error == 0) {
		logger(DEBUG_PROTOCOL, LOG_INFO, "[upnp] Successfully set port mapping (%s:%s %s for %s seconds)", myaddr, port, proto, lease_duration);
	} else {
		logger(DEBUG_PROTOCOL, LOG_ERR, "[upnp] Failed to set port mapping (%s:%s %s for %s seconds): [%d] %s", myaddr, port, proto, lease_duration, error, strupnperror(error));
	}

	free(port);
}

static void upnp_refresh() {
	logger(DEBUG_PROTOCOL, LOG_INFO, "[upnp] Discovering IGD devices");

	int error;
	struct UPNPDev *devices = upnp_discover(upnp_discover_wait * 1000, &error);

	if(!devices) {
		logger(DEBUG_PROTOCOL, LOG_WARNING, "[upnp] Unable to find IGD devices: [%d] %s", error, strupnperror(error));
		freeUPNPDevlist(devices);
		return;
	}

	struct UPNPUrls urls;

	struct IGDdatas data;

	char myaddr[64];

	int result = UPNP_GetValidIGD(devices, &urls, &data, myaddr, sizeof(myaddr));

	if(result <= 0) {
		logger(DEBUG_PROTOCOL, LOG_WARNING, "[upnp] No IGD found");
		freeUPNPDevlist(devices);
		return;
	}

	logger(DEBUG_PROTOCOL, LOG_INFO, "[upnp] IGD found: [%d] %s (local address: %s, service type: %s)", result, urls.controlURL, myaddr, data.first.servicetype);

	for(int i = 0; i < listen_sockets; i++) {
		if(upnp_tcp) {
			upnp_add_mapping(&urls, &data, myaddr, listen_socket[i].tcp.fd, "TCP");
		}

		if(upnp_udp) {
			upnp_add_mapping(&urls, &data, myaddr, listen_socket[i].udp.fd, "UDP");
		}
	}

	FreeUPNPUrls(&urls);
	freeUPNPDevlist(devices);
}

static void *upnp_thread(void *data) {
	(void)data;

	while(true) {
		time_t start = time(NULL);
		upnp_refresh();

		// Make sure we'll stick to the refresh period no matter how long upnp_refresh() takes.
		time_t refresh_time = start + upnp_refresh_period;
		time_t now = time(NULL);

		if(now < refresh_time) {
			nanosleep(&(struct timespec) {
				refresh_time - now, 0
			}, NULL);
		}
	}

	// TODO: we don't have a clean thread shutdown procedure, so we can't remove the mapping.
	//       this is probably not a concern as long as the UPnP device honors the lease duration,
	//       but considering how bug-riddled these devices often are, that's a big "if".
	return NULL;
}

void upnp_init(bool tcp, bool udp) {
	upnp_tcp = tcp;
	upnp_udp = udp;

	get_config_int(lookup_config(config_tree, "UPnPDiscoverWait"), &upnp_discover_wait);
	get_config_int(lookup_config(config_tree, "UPnPRefreshPeriod"), &upnp_refresh_period);

#ifdef HAVE_MINGW
	HANDLE handle = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)upnp_thread, NULL, 0, NULL);

	if(!handle) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Unable to start UPnP-IGD client thread");
	}

#else
	pthread_t thread;
	int error = pthread_create(&thread, NULL, upnp_thread, NULL);

	if(error) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Unable to start UPnP-IGD client thread: [%d] %s", error, strerror(error));
	}

#endif
}
