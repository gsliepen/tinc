/*
    device.h -- generic header for device.c
    Copyright (C) 2001-2005 Ivo Timmermans
                  2001-2012 Guus Sliepen <guus@tinc-vpn.org>

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

#ifndef __TINC_DEVICE_H__
#define __TINC_DEVICE_H__

#include "net.h"

extern int device_fd;
extern char *device;
extern char *iface;

typedef struct devops_t {
	bool (*setup)(void);
	void (*close)(void);
	bool (*read)(struct vpn_packet_t *);
	bool (*write)(struct vpn_packet_t *);
	void (*enable)(void);   /* optional */
	void (*disable)(void);  /* optional */
} devops_t;

extern const devops_t os_devops;
extern const devops_t dummy_devops;
extern const devops_t raw_socket_devops;
extern const devops_t multicast_devops;
extern const devops_t fd_devops;
extern const devops_t uml_devops;
extern const devops_t vde_devops;
extern devops_t devops;

#endif /* __TINC_DEVICE_H__ */
