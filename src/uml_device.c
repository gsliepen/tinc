/*
    device.c -- UML network socket
    Copyright (C) 2002-2005 Ivo Timmermans,
                  2002-2017 Guus Sliepen <guus@tinc-vpn.org>

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

#include <sys/un.h>

#include "conf.h"
#include "device.h"
#include "names.h"
#include "net.h"
#include "logger.h"
#include "utils.h"
#include "route.h"
#include "xalloc.h"

static int listen_fd = -1;
static int request_fd = -1;
static int data_fd = -1;
static int write_fd = -1;
static int state = 0;
static const char *device_info = NULL;

enum request_type { REQ_NEW_CONTROL };

static struct request {
	uint32_t magic;
	uint32_t version;
	enum request_type type;
	struct sockaddr_un sock;
} request;

static struct sockaddr_un data_sun = {
	.sun_family = AF_UNIX,
};

static bool setup_device(void) {
	device_info = _("UML network socket");

	struct sockaddr_un listen_sun = {
		.sun_family = AF_UNIX,
	};
	static const int one = 1;
	struct {
		char zero;
		int pid;
		int usecs;
	} name;
	struct timeval tv;

	if(!get_config_string(lookup_config(&config_tree, "Device"), &device)) {
		xasprintf(&device, RUNSTATEDIR "/%s.umlsocket", identname);
	}

	get_config_string(lookup_config(&config_tree, "Interface"), &iface);

	if((write_fd = socket(PF_UNIX, SOCK_DGRAM, 0)) < 0) {
		logger(DEBUG_ALWAYS, LOG_ERR, _("Could not open write %s: %s"), device_info, strerror(errno));
		event_exit();
		return false;
	}

#ifdef FD_CLOEXEC
	fcntl(write_fd, F_SETFD, FD_CLOEXEC);
#endif

	setsockopt(write_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

	if(fcntl(write_fd, F_SETFL, O_NONBLOCK) < 0) {
		logger(DEBUG_ALWAYS, LOG_ERR, _("System call `%s' failed: %s"), "fcntl", strerror(errno));
		event_exit();
		return false;
	}

	if((data_fd = socket(PF_UNIX, SOCK_DGRAM, 0)) < 0) {
		logger(DEBUG_ALWAYS, LOG_ERR, _("Could not open data %s: %s"), device_info, strerror(errno));
		event_exit();
		return false;
	}

#ifdef FD_CLOEXEC
	fcntl(data_fd, F_SETFD, FD_CLOEXEC);
#endif

	setsockopt(data_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

	if(fcntl(data_fd, F_SETFL, O_NONBLOCK) < 0) {
		logger(DEBUG_ALWAYS, LOG_ERR, _("System call `%s' failed: %s"), "fcntl", strerror(errno));
		event_exit();
		return false;
	}

	name.zero = 0;
	name.pid = getpid();
	gettimeofday(&tv, NULL);
	name.usecs = (int) tv.tv_usec;
	memcpy(&data_sun.sun_path, &name, sizeof(name));

	if(bind(data_fd, (struct sockaddr *)&data_sun, sizeof(data_sun)) < 0) {
		logger(DEBUG_ALWAYS, LOG_ERR, _("Could not bind data %s: %s"), device_info, strerror(errno));
		event_exit();
		return false;
	}

	if((listen_fd = socket(PF_UNIX, SOCK_STREAM, 0)) < 0) {
		logger(DEBUG_ALWAYS, LOG_ERR, _("Could not open %s: %s"), device_info,
		       strerror(errno));
		return false;
	}

#ifdef FD_CLOEXEC
	fcntl(device_fd, F_SETFD, FD_CLOEXEC);
#endif

	setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

	if(fcntl(listen_fd, F_SETFL, O_NONBLOCK) < 0) {
		logger(DEBUG_ALWAYS, LOG_ERR, _("System call `%s' failed: %s"), "fcntl", strerror(errno));
		return false;
	}

	if(strlen(device) >= sizeof(listen_sun.sun_path)) {
		logger(DEBUG_ALWAYS, LOG_ERR, _("UML socket filename %s is too long!"), device);
		return false;
	}

	strncpy(listen_sun.sun_path, device, sizeof(listen_sun.sun_path));

	if(bind(listen_fd, (struct sockaddr *)&listen_sun, sizeof(listen_sun)) < 0) {
		logger(DEBUG_ALWAYS, LOG_ERR, _("Could not bind %s to %s: %s"), device_info, device, strerror(errno));
		return false;
	}

	if(listen(listen_fd, 1) < 0) {
		logger(DEBUG_ALWAYS, LOG_ERR, _("Could not listen on %s %s: %s"), device_info, device, strerror(errno));
		return false;
	}

	device_fd = listen_fd;
	state = 0;

	logger(DEBUG_ALWAYS, LOG_INFO, _("%s is a %s"), device, device_info);

	if(routing_mode == RMODE_ROUTER) {
		overwrite_mac = true;
	}

	return true;
}

void close_device(void) {
	if(listen_fd >= 0) {
		close(listen_fd);
		listen_fd = -1;
	}

	if(request_fd >= 0) {
		close(request_fd);
		request_fd = -1;
	}

	if(data_fd >= 0) {
		close(data_fd);
		data_fd = -1;
	}

	if(write_fd >= 0) {
		close(write_fd);
		write_fd = -1;
	}

	unlink(device);

	free(device);
	device = NULL;

	free(iface);
	iface = NULL;

	device_info = NULL;
}

static bool read_packet(vpn_packet_t *packet) {
	ssize_t inlen;

	switch(state) {
	case 0: {
		struct sockaddr sa;
		socklen_t salen = sizeof(sa);

		request_fd = accept(listen_fd, &sa, &salen);

		if(request_fd < 0) {
			logger(DEBUG_ALWAYS, LOG_ERR, _("Could not accept connection to %s %s: %s"), device_info, device, strerror(errno));
			return false;
		}

#ifdef FD_CLOEXEC
		fcntl(request_fd, F_SETFD, FD_CLOEXEC);
#endif

		if(fcntl(listen_fd, F_SETFL, O_NONBLOCK) < 0) {
			logger(DEBUG_ALWAYS, LOG_ERR, _("System call `%s' failed: %s"), "fcntl", strerror(errno));
			event_exit();
			return false;
		}

		close(listen_fd);
		listen_fd = -1;
		device_fd = request_fd;
		state = 1;

		return false;
	}

	case 1: {
		if((inlen = read(request_fd, &request, sizeof(request))) != sizeof(request)) {
			logger(DEBUG_ALWAYS, LOG_ERR, _("Error while reading request from %s %s: %s"), device_info,
			       device, strerror(errno));
			event_exit();
			return false;
		}

		if(request.magic != 0xfeedface || request.version != 3 || request.type != REQ_NEW_CONTROL) {
			logger(DEBUG_ALWAYS, LOG_ERR, _("Unknown magic %x, version %d, request type %d from %s %s"),
			       request.magic, request.version, request.type, device_info, device);
			event_exit();
			return false;
		}

		if(connect(write_fd, (const struct sockaddr *)&request.sock, sizeof(request.sock)) < 0) {
			logger(DEBUG_ALWAYS, LOG_ERR, _("Could not bind write %s: %s"), device_info, strerror(errno));
			event_exit();
			return false;
		}

		write(request_fd, &data_sun, sizeof(data_sun));
		device_fd = data_fd;

		logger(DEBUG_ALWAYS, LOG_INFO, _("Connection with UML established"));

		state = 2;
		return false;
	}

	case 2: {
		if((inlen = read(data_fd, DATA(packet), MTU)) <= 0) {
			logger(DEBUG_ALWAYS, LOG_ERR, _("Error while reading from %s %s: %s"), device_info,
			       device, strerror(errno));
			event_exit();
			return false;
		}

		packet->len = inlen;

		logger(DEBUG_TRAFFIC, LOG_DEBUG, _("Read packet of %d bytes from %s"), packet->len,
		       device_info);

		return true;
	}

	default:
		logger(DEBUG_ALWAYS, LOG_ERR, _("Invalid value for state variable in %s"), __FILE__);
		abort();
	}
}

static bool write_packet(vpn_packet_t *packet) {
	if(state != 2) {
		logger(DEBUG_TRAFFIC, LOG_DEBUG, _("Dropping packet of %d bytes to %s: not connected to UML yet"),
		       packet->len, device_info);
		return false;
	}

	logger(DEBUG_TRAFFIC, LOG_DEBUG, _("Writing packet of %d bytes to %s"),
	       packet->len, device_info);

	if(write(write_fd, DATA(packet), packet->len) < 0) {
		if(errno != EINTR && errno != EAGAIN) {
			logger(DEBUG_ALWAYS, LOG_ERR, _("Can't write to %s %s: %s"), device_info, device, strerror(errno));
			event_exit();
		}

		return false;
	}

	return true;
}

const devops_t uml_devops = {
	.setup = setup_device,
	.close = close_device,
	.read = read_packet,
	.write = write_packet,
};
