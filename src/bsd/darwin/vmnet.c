/*
 *  vmnet - macOS vmnet device support
 *  Copyright (C) 2024 Eric Karge
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include "vmnet.h"
#include <stdint.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/socket.h>
#include <vmnet/vmnet.h>
#include <dispatch/dispatch.h>
#include "../../logger.h"
#include <errno.h>

static volatile vmnet_return_t if_status = VMNET_SETUP_INCOMPLETE;
static dispatch_queue_t if_queue;
static interface_ref vmnet_if;
static size_t max_packet_size;
static struct iovec read_iov_in;
static int read_socket[2];

static void macos_vmnet_read(void);
static const char *str_vmnet_status(vmnet_return_t status);

int macos_vmnet_open(const char device[]) {
	if(socketpair(AF_UNIX, SOCK_DGRAM, 0, read_socket)) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Unable to create socket: %s", strerror(errno));
		return -1;
	}

	xpc_object_t if_desc = xpc_dictionary_create(NULL, NULL, 0);
	xpc_dictionary_set_uint64(if_desc, vmnet_operation_mode_key,
			!strncmp(device, "vmnet-bridged", 14) ? VMNET_BRIDGED_MODE :
			!strncmp(device, "vmnet-shared", 13) ? VMNET_SHARED_MODE :
			VMNET_HOST_MODE
	);
	xpc_dictionary_set_bool(if_desc, vmnet_enable_isolation_key, 0);
	xpc_dictionary_set_bool(if_desc, vmnet_allocate_mac_address_key, false);
	if (macos_vmnet_addr) {
		xpc_dictionary_set_string(if_desc, vmnet_start_address_key, macos_vmnet_addr);
		xpc_dictionary_set_string(if_desc, vmnet_end_address_key, macos_vmnet_addr);
		xpc_dictionary_set_string(if_desc, vmnet_subnet_mask_key, macos_vmnet_netmask);
	}
	if (macos_vmnet_bridged_if) {
		xpc_dictionary_set_string(if_desc, vmnet_shared_interface_name_key, macos_vmnet_bridged_if);
	}
	if (macos_vmnet_nat66_prefix) {
			xpc_dictionary_set_string(if_desc, vmnet_nat66_prefix_key, macos_vmnet_nat66_prefix);
	}

	if_queue = dispatch_queue_create("org.tinc-vpn.vmnet.if_queue", DISPATCH_QUEUE_SERIAL);

	dispatch_semaphore_t if_started_sem = dispatch_semaphore_create(0);
	vmnet_if = vmnet_start_interface(
		if_desc, if_queue,
		^(vmnet_return_t status, xpc_object_t interface_param) {
			if_status = status;
			if(status == VMNET_SUCCESS && interface_param) {
				max_packet_size = xpc_dictionary_get_uint64(interface_param, vmnet_max_packet_size_key);
			}
			dispatch_semaphore_signal(if_started_sem);
		});
	if (vmnet_if) {
		dispatch_semaphore_wait(if_started_sem, DISPATCH_TIME_FOREVER);
	}
	dispatch_release(if_started_sem);

	if (if_status == VMNET_SUCCESS) {
		read_iov_in.iov_base = malloc(max_packet_size);
		read_iov_in.iov_len = max_packet_size;

		if_status = vmnet_interface_set_event_callback(
			vmnet_if, VMNET_INTERFACE_PACKETS_AVAILABLE, if_queue,
			^(interface_event_t event_type, xpc_object_t event) {
				macos_vmnet_read();
			});
	}

	xpc_release(if_desc);

	if(if_status != VMNET_SUCCESS) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Unable to create vmnet device: %s", str_vmnet_status(if_status));
		if (vmnet_if) {
			vmnet_stop_interface(vmnet_if, if_queue, ^(vmnet_return_t result) {});
			vmnet_if = NULL;
		}
		if_status = VMNET_SETUP_INCOMPLETE;
		dispatch_release(if_queue);
		close(read_socket[0]);
		close(read_socket[1]);
		return -1;
	}

	return read_socket[0];
}

int macos_vmnet_close(int fd) {
	if(vmnet_if == NULL || fd != read_socket[0]) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Unable to close vmnet device: device not setup properly");
		return -1;
	}

	dispatch_semaphore_t if_stopped_sem = dispatch_semaphore_create(0);
	if_status = vmnet_stop_interface(
		vmnet_if, if_queue,
		^(vmnet_return_t status) {
			if_status = status;
			dispatch_semaphore_signal(if_stopped_sem);
		});
	if (if_status == VMNET_SUCCESS) {
		dispatch_semaphore_wait(if_stopped_sem, DISPATCH_TIME_FOREVER);
	}
	dispatch_release(if_stopped_sem);

	if(if_status != VMNET_SUCCESS) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Unable to close vmnet device: %s", str_vmnet_status(if_status));
		return -1;
	}

	if_status = VMNET_SETUP_INCOMPLETE;
	dispatch_release(if_queue);

	read_iov_in.iov_len = 0;
	free(read_iov_in.iov_base);
	read_iov_in.iov_base = NULL;

	close(read_socket[0]);
	close(read_socket[1]);

	return 0;
}

void macos_vmnet_read(void) {
	if(if_status != VMNET_SUCCESS) {
		return;
	}

	int pkt_count = 1;
	struct vmpktdesc packet = {
		.vm_flags = 0,
		.vm_pkt_size = max_packet_size,
		.vm_pkt_iov = &read_iov_in,
		.vm_pkt_iovcnt = 1,
	};

	if_status = vmnet_read(vmnet_if, &packet, &pkt_count);
	if(if_status != VMNET_SUCCESS) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Unable to read packet: %s", str_vmnet_status(if_status));
		return;
	}

	if(pkt_count && packet.vm_pkt_iovcnt) {
		struct iovec read_iov_out = {
			.iov_base = packet.vm_pkt_iov->iov_base,
			.iov_len = packet.vm_pkt_size,
		};
		if(writev(read_socket[1], &read_iov_out, 1) < 0) {
			logger(DEBUG_ALWAYS, LOG_ERR, "Unable to write to read socket: %s", strerror(errno));
			return;
		}
	}
}

ssize_t macos_vmnet_write(uint8_t *buffer, size_t buflen) {
	if(buflen > max_packet_size) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Max packet size (%zd) exceeded: %zd", max_packet_size, buflen);
		return -1;
	}

	struct iovec iov = {
		.iov_base = (char *) buffer,
		.iov_len = buflen,
	};
	struct vmpktdesc packet = {
		.vm_pkt_iovcnt = 1,
		.vm_flags = 0,
		.vm_pkt_size = buflen,
		.vm_pkt_iov = &iov,
	};
	int pkt_count = 1;

	vmnet_return_t result = vmnet_write(vmnet_if, &packet, &pkt_count);
	if(result != VMNET_SUCCESS) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Write failed: %s", str_vmnet_status(result));
		return -1;
	}

	return pkt_count ? buflen : 0;
}

const char *str_vmnet_status(vmnet_return_t status) {
	switch (status) {
	case VMNET_SUCCESS:
		return "success";
	case VMNET_FAILURE:
		return "general failure (possibly not enough privileges)";
	case VMNET_MEM_FAILURE:
		return "memory allocation failure";
	case VMNET_INVALID_ARGUMENT:
		return "invalid argument specified";
	case VMNET_SETUP_INCOMPLETE:
		return "interface setup is not complete";
	case VMNET_INVALID_ACCESS:
		return "invalid access, permission denied";
	case VMNET_PACKET_TOO_BIG:
		return "packet size is larger than MTU";
	case VMNET_BUFFER_EXHAUSTED:
		return "buffers exhausted in kernel";
	case VMNET_TOO_MANY_PACKETS:
		return "packet count exceeds limit";
	case VMNET_SHARING_SERVICE_BUSY:
		return "conflict, sharing service is in use";
	default:
		return "unknown vmnet error";
	}
}
