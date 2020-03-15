/*
    fd_device.c -- Interaction with Android tun fd
    Copyright (C)   2001-2005   Ivo Timmermans,
                    2001-2016   Guus Sliepen <guus@tinc-vpn.org>
                    2009        Grzegorz Dymarek <gregd72002@googlemail.com>
                    2016-2020   Pacien TRAN-GIRARD <pacien@pacien.net>

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

#include <sys/un.h>

#include "system.h"
#include "conf.h"
#include "device.h"
#include "ethernet.h"
#include "logger.h"
#include "net.h"
#include "route.h"
#include "utils.h"

struct unix_socket_addr {
	size_t size;
	struct sockaddr_un addr;
};

static int read_fd(int socket) {
	char iobuf;
	struct iovec iov = {0};
	char cmsgbuf[CMSG_SPACE(sizeof(device_fd))];
	struct msghdr msg = {0};
	int ret;
	struct cmsghdr *cmsgptr;

	iov.iov_base = &iobuf;
	iov.iov_len = 1;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = cmsgbuf;
	msg.msg_controllen = sizeof(cmsgbuf);

	if((ret = recvmsg(socket, &msg, 0)) < 1) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Could not read from unix socket (error %d)!", ret);
		return -1;
	}
#ifdef IP_RECVERR
	if(msg.msg_flags & (MSG_CTRUNC | MSG_OOB | MSG_ERRQUEUE)) {
#else
	if(msg.msg_flags & (MSG_CTRUNC | MSG_OOB)) {
#endif
		logger(DEBUG_ALWAYS, LOG_ERR, "Error while receiving message (flags %d)!", msg.msg_flags);
		return -1;
	}

	cmsgptr = CMSG_FIRSTHDR(&msg);
	if(cmsgptr->cmsg_level != SOL_SOCKET) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Wrong CMSG level: %d, expected %d!",
			cmsgptr->cmsg_level, SOL_SOCKET);
		return -1;
	}
	if(cmsgptr->cmsg_type != SCM_RIGHTS) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Wrong CMSG type: %d, expected %d!",
			cmsgptr->cmsg_type, SCM_RIGHTS);
		return -1;
	}
	if(cmsgptr->cmsg_len != CMSG_LEN(sizeof(device_fd))) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Wrong CMSG data length: %lu, expected %lu!",
			(unsigned long)cmsgptr->cmsg_len, CMSG_LEN(sizeof(device_fd)));
		return -1;
	}

	return *(int *) CMSG_DATA(cmsgptr);
}

static int receive_fd(struct unix_socket_addr socket_addr) {
	int socketfd;
	int ret;
	int result;

	if((socketfd = socket(PF_UNIX, SOCK_STREAM, 0)) < 0) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Could not open stream socket (error %d)!", socketfd);
		return -1;
	}

	if((ret = connect(socketfd, (struct sockaddr *) &socket_addr.addr, socket_addr.size)) < 0) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Could not connect to Unix socket (error %d)!", ret);
		result = -1;
		goto end;
	}

	result = read_fd(socketfd);

end:
	close(socketfd);
	return result;
}

static struct unix_socket_addr parse_socket_addr(const char *path) {
	struct sockaddr_un socket_addr;
	size_t path_length;

	if(strlen(path) >= sizeof(socket_addr.sun_path)) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Unix socket path too long!");
		return (struct unix_socket_addr) {0};
	}

	socket_addr.sun_family = AF_UNIX;
	strncpy(socket_addr.sun_path, path, sizeof(socket_addr.sun_path));

	if(path[0] == '@') {
		/* abstract namespace socket */
		socket_addr.sun_path[0] = '\0';
		path_length = strlen(path);
	} else {
		/* filesystem path with NUL terminator */
		path_length = strlen(path) + 1;
	}

	return (struct unix_socket_addr) {
		.size = offsetof(struct sockaddr_un, sun_path) + path_length,
		.addr = socket_addr
	};
}

static bool setup_device(void) {
	if(routing_mode == RMODE_SWITCH) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Switch mode not supported (requires unsupported TAP device)!");
		return false;
	}

	if(!get_config_string(lookup_config(config_tree, "Device"), &device)) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Could not read device from configuration!");
		return false;
	}

	/* device is either directly a file descriptor or an unix socket to read it from */
	if(sscanf(device, "%d", &device_fd) != 1) {
		logger(DEBUG_ALWAYS, LOG_INFO, "Receiving fd from Unix socket at %s.", device);
		device_fd = receive_fd(parse_socket_addr(device));
	}

	if(device_fd < 0) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Could not open %s: %s!", device, strerror(errno));
		return false;
	}

	logger(DEBUG_ALWAYS, LOG_INFO, "fd/%d adapter set up.", device_fd);

	return true;
}

static void close_device(void) {
	close(device_fd);
	device_fd = -1;
}

static inline uint16_t get_ip_ethertype(vpn_packet_t *packet) {
	switch(DATA(packet)[ETH_HLEN] >> 4) {
	case 4:
		return ETH_P_IP;

	case 6:
		return ETH_P_IPV6;

	default:
		return ETH_P_MAX;
	}
}

static inline void set_etherheader(vpn_packet_t *packet, uint16_t ethertype) {
	memset(DATA(packet), 0, ETH_HLEN - ETHER_TYPE_LEN);

	DATA(packet)[ETH_HLEN - ETHER_TYPE_LEN] = (ethertype >> 8) & 0xFF;
	DATA(packet)[ETH_HLEN - ETHER_TYPE_LEN + 1] = ethertype & 0xFF;
}

static bool read_packet(vpn_packet_t *packet) {
	int lenin = read(device_fd, DATA(packet) + ETH_HLEN, MTU - ETH_HLEN);

	if(lenin <= 0) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Error while reading from fd/%d: %s!", device_fd, strerror(errno));
		return false;
	}

	uint16_t ethertype = get_ip_ethertype(packet);

	if(ethertype == ETH_P_MAX) {
		logger(DEBUG_TRAFFIC, LOG_ERR, "Unknown IP version while reading packet from fd/%d!", device_fd);
		return false;
	}

	set_etherheader(packet, ethertype);
	packet->len = lenin + ETH_HLEN;

	logger(DEBUG_TRAFFIC, LOG_DEBUG, "Read packet of %d bytes from fd/%d.", packet->len, device_fd);

	return true;
}

static bool write_packet(vpn_packet_t *packet) {
	logger(DEBUG_TRAFFIC, LOG_DEBUG, "Writing packet of %d bytes to fd/%d.", packet->len, device_fd);

	if(write(device_fd, DATA(packet) + ETH_HLEN, packet->len - ETH_HLEN) < 0) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Error while writing to fd/%d: %s!", device_fd, strerror(errno));
		return false;
	}

	return true;
}

const devops_t fd_devops = {
	.setup = setup_device,
	.close = close_device,
	.read = read_packet,
	.write = write_packet,
};
