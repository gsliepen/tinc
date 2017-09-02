/*
    top.c -- Show real-time statistics from a running tincd
    Copyright (C) 2011-2013 Guus Sliepen <guus@tinc-vpn.org>

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

#ifdef HAVE_CURSES

#undef KEY_EVENT  /* There are conflicting declarations for KEY_EVENT in Windows wincon.h and curses.h. */
#include <curses.h>

#include "control_common.h"
#include "list.h"
#include "names.h"
#include "tincctl.h"
#include "top.h"
#include "xalloc.h"

typedef struct nodestats_t {
	char *name;
	int i;
	uint64_t in_packets;
	uint64_t in_bytes;
	uint64_t out_packets;
	uint64_t out_bytes;
	float in_packets_rate;
	float in_bytes_rate;
	float out_packets_rate;
	float out_bytes_rate;
	bool known;
} nodestats_t;

static const char *const sortname[] = {
	"name",
	"in pkts",
	"in bytes",
	"out pkts",
	"out bytes",
	"tot pkts",
	"tot bytes",
};

static int sortmode = 0;
static bool cumulative = false;

static list_t node_list;
static struct timeval cur, prev, diff;
static int delay = 1000;
static bool changed = true;
static const char *bunit = "bytes";
static float bscale = 1;
static const char *punit = "pkts";
static float pscale = 1;

static bool update(int fd) {
	if(!sendline(fd, "%d %d", CONTROL, REQ_DUMP_TRAFFIC))
		return false;

	gettimeofday(&cur, NULL);

	timersub(&cur, &prev, &diff);
	prev = cur;
	float interval = diff.tv_sec + diff.tv_usec * 1e-6;

	char line[4096];
	char name[4096];
	int code;
	int req;
	uint64_t in_packets;
	uint64_t in_bytes;
	uint64_t out_packets;
	uint64_t out_bytes;

	for list_each(nodestats_t, ns, &node_list)
		ns->known = false;

	while(recvline(fd, line, sizeof line)) {
		int n = sscanf(line, "%d %d %4095s %"PRIu64" %"PRIu64" %"PRIu64" %"PRIu64, &code, &req, name, &in_packets, &in_bytes, &out_packets, &out_bytes);

		if(n == 2)
			return true;

		if(n != 7)
			return false;

		nodestats_t *found = NULL;

		for list_each(nodestats_t, ns, &node_list) {
			int result = strcmp(name, ns->name);
			if(result > 0) {
				continue;
			} if(result == 0) {
				found = ns;
				break;
			} else {
				found = xzalloc(sizeof *found);
				found->name = xstrdup(name);
				list_insert_before(&node_list, node, found);
				changed = true;
				break;
			}
		}

		if(!found) {
			found = xzalloc(sizeof *found);
			found->name = xstrdup(name);
			list_insert_tail(&node_list, found);
			changed = true;
		}

		found->known = true;
		found->in_packets_rate = (in_packets - found->in_packets) / interval;
		found->in_bytes_rate = (in_bytes - found->in_bytes) / interval;
		found->out_packets_rate = (out_packets - found->out_packets) / interval;
		found->out_bytes_rate = (out_bytes - found->out_bytes) / interval;
		found->in_packets = in_packets;
		found->in_bytes = in_bytes;
		found->out_packets = out_packets;
		found->out_bytes = out_bytes;
	}

	return false;
}

static int cmpfloat(float a, float b) {
	if(a < b)
		return -1;
	else if(a > b)
		return 1;
	else
		return 0;
}

static int cmpu64(uint64_t a, uint64_t b) {
	if(a < b)
		return -1;
	else if(a > b)
		return 1;
	else
		return 0;
}

static int sortfunc(const void *a, const void *b) {
	const nodestats_t *na = *(const nodestats_t **)a;
	const nodestats_t *nb = *(const nodestats_t **)b;
	int result;

	switch(sortmode) {
		case 1:
			if(cumulative)
				result = -cmpu64(na->in_packets, nb->in_packets);
			else
				result = -cmpfloat(na->in_packets_rate, nb->in_packets_rate);
			break;
		case 2:
			if(cumulative)
				result = -cmpu64(na->in_bytes, nb->in_bytes);
			else
				result = -cmpfloat(na->in_bytes_rate, nb->in_bytes_rate);
			break;
		case 3:
			if(cumulative)
				result = -cmpu64(na->out_packets, nb->out_packets);
			else
				result = -cmpfloat(na->out_packets_rate, nb->out_packets_rate);
			break;
		case 4:
			if(cumulative)
				result = -cmpu64(na->out_bytes, nb->out_bytes);
			else
				result = -cmpfloat(na->out_bytes_rate, nb->out_bytes_rate);
			break;
		case 5:
			if(cumulative)
				result = -cmpu64(na->in_packets + na->out_packets, nb->in_packets + nb->out_packets);
			else
				result = -cmpfloat(na->in_packets_rate + na->out_packets_rate, nb->in_packets_rate + nb->out_packets_rate);
			break;
		case 6:
			if(cumulative)
				result = -cmpu64(na->in_bytes + na->out_bytes, nb->in_bytes + nb->out_bytes);
			else
				result = -cmpfloat(na->in_bytes_rate + na->out_bytes_rate, nb->in_bytes_rate + nb->out_bytes_rate);
			break;
		default:
			result = strcmp(na->name, nb->name);
			break;
	}

	if(result)
		return result;
	else
		return na->i - nb->i;
}

static void redraw(void) {
	erase();

	mvprintw(0, 0, "Tinc %-16s  Nodes: %4d  Sort: %-10s  %s", netname ?: "", node_list.count, sortname[sortmode], cumulative ? "Cumulative" : "Current");
	attrset(A_REVERSE);
	mvprintw(2, 0, "Node                IN %s   IN %s   OUT %s  OUT %s", punit, bunit, punit, bunit);
	chgat(-1, A_REVERSE, 0, NULL);

	static nodestats_t **sorted = 0;
	static int n = 0;
	if(changed) {
		n = 0;
		sorted = xrealloc(sorted, node_list.count * sizeof *sorted);
		for list_each(nodestats_t, ns, &node_list)
			sorted[n++] = ns;
		changed = false;
	}

	for(int i = 0; i < n; i++)
		sorted[i]->i = i;

	if(sorted)
		qsort(sorted, n, sizeof *sorted, sortfunc);

	for(int i = 0, row = 3; i < n; i++, row++) {
		nodestats_t *node = sorted[i];
		if(node->known)
			if(node->in_packets_rate || node->out_packets_rate)
				attrset(A_BOLD);
			else
				attrset(A_NORMAL);
		else
			attrset(A_DIM);

		if(cumulative)
			mvprintw(row, 0, "%-16s %10.0f %10.0f %10.0f %10.0f",
					node->name, node->in_packets * pscale, node->in_bytes * bscale, node->out_packets * pscale, node->out_bytes * bscale);
		else
			mvprintw(row, 0, "%-16s %10.0f %10.0f %10.0f %10.0f",
					node->name, node->in_packets_rate * pscale, node->in_bytes_rate * bscale, node->out_packets_rate * pscale, node->out_bytes_rate * bscale);
	}

	attrset(A_NORMAL);
	move(1, 0);

	refresh();
}

void top(int fd) {
	initscr();
	timeout(delay);
	bool running = true;

	while(running) {
		if(!update(fd))
			break;

		redraw();

		switch(getch()) {
			case 's': {
				timeout(-1);
				float input = delay * 1e-3;
				mvprintw(1, 0, "Change delay from %.1fs to: ", input);
				scanw("%f", &input);
				if(input < 0.1)
					input = 0.1;
				delay = input * 1e3;
				timeout(delay);
				break;
			}
			case 'c':
				cumulative = !cumulative;
				break;
			case 'n':
				sortmode = 0;
				break;
			case 'i':
				sortmode = 2;
				break;
			case 'I':
				sortmode = 1;
				break;
			case 'o':
				sortmode = 4;
				break;
			case 'O':
				sortmode = 3;
				break;
			case 't':
				sortmode = 6;
				break;
			case 'T':
				sortmode = 5;
				break;
			case 'b':
				bunit = "bytes";
				bscale = 1;
				punit = "pkts";
				pscale = 1;
				break;
			case 'k':
				bunit = "kbyte";
				bscale = 1e-3;
				punit = "pkts";
				pscale = 1;
				break;
			case 'M':
				bunit = "Mbyte";
				bscale = 1e-6;
				punit = "kpkt";
				pscale = 1e-3;
				break;
			case 'G':
				bunit = "Gbyte";
				bscale = 1e-9;
				punit = "Mpkt";
				pscale = 1e-6;
				break;
			case 'q':
			case KEY_BREAK:
				running = false;
				break;
			default:
				break;
		}
	}

	endwin();
}

#endif
