#ifndef TINC_ASYNC_SEND_H
#define TINC_ASYNC_SEND_H

/*
    async_send.h -- asynchronous send() functions
    Copyright (C) 2018 Etienne Dechamps <etienne@edechamps.fr>

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

extern void async_send_init();
extern void async_send_exit();
extern void async_sendto(int fd, const void* buf, size_t len, int flags, const sockaddr_t *dest_addr);

#endif
