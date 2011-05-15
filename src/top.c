/*
    top.c -- Show real-time statistics from a running tincd
    Copyright (C) 2011 Guus Sliepen <guus@tinc-vpn.org>

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

#include <curses.h>

#include "control_common.h"
#include "tincctl.h"
#include "top.h"

void top(int fd) {
	initscr();

	timeout(1000);

	do {
		sendline(fd, "%d %d", CONTROL, REQ_DUMP_TRAFFIC);

		erase();

		char line[4096];
		while(recvline(fd, line, sizeof line)) {
			char node[4096];
			int code;
			int req;
			uint64_t in_packets;
			uint64_t in_bytes;
			uint64_t out_packets;
			uint64_t out_bytes;

			int n = sscanf(line, "%d %d %s %"PRIu64" %"PRIu64" %"PRIu64" %"PRIu64, &code, &req, node, &in_packets, &in_bytes, &out_packets, &out_bytes);

			if(n == 2)
				break;

			if(n != 7) {
				fprintf(stderr, "Error receiving traffic information\n");
				return;
			}

			printw("%16s %8"PRIu64" %8"PRIu64" %8"PRIu64" %8"PRIu64"\n", node, in_packets, in_bytes, out_packets, out_bytes);
		}

		refresh();

	} while(getch() == ERR);

	endwin();
}
