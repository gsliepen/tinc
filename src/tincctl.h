/*
    tincctl.h -- header for tincctl.c.
    Copyright (C) 2011-2016 Guus Sliepen <guus@tinc-vpn.org>

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

#ifndef __TINC_TINCCTL_H__
#define __TINC_TINCCTL_H__

extern bool tty;
extern bool force;
extern char line[4096];
extern int fd;
extern char buffer[4096];
extern size_t blen;
extern bool confbasegiven;
extern char *tinc_conf;
extern char *hosts_dir;

#define VAR_SERVER 1    /* Should be in tinc.conf */
#define VAR_HOST 2      /* Can be in host config file */
#define VAR_MULTIPLE 4  /* Multiple statements allowed */
#define VAR_OBSOLETE 8  /* Should not be used anymore */
#define VAR_SAFE 16     /* Variable is safe when accepting invitations */

typedef struct {
	const char *name;
	int type;
} var_t;

extern const var_t variables[];

extern int rstrip(char *value);
extern char *get_my_name(bool verbose);
extern bool connect_tincd(bool verbose);
extern bool sendline(int fd, char *format, ...);
extern bool recvline(int fd, char *line, size_t len);
extern int check_port(char *name);
extern FILE *fopenmask(const char *filename, const char *mode, mode_t perms);
extern ecdsa_t *get_pubkey(FILE *f);

#endif

