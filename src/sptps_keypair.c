/*
    sptps_test.c -- Simple Peer-to-Peer Security test program
    Copyright (C) 2011-2013 Guus Sliepen <guus@tinc-vpn.org>,

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

#include <getopt.h>

#include "crypto.h"
#include "ecdsagen.h"
#include "utils.h"

static char *program_name;

void logger(int level, int priority, const char *format, ...) {
	(void)level;
	(void)priority;
	va_list ap;

	va_start(ap, format);
	vfprintf(stderr, format, ap);
	va_end(ap);

	fputc('\n', stderr);
}

static void usage() {
	fprintf(stderr, "Usage: %s [options] private_key_file public_key_file\n\n", program_name);
	fprintf(stderr, "Valid options are:\n"
	        "  --help  Display this help and exit.\n"
	        "\n");
	fprintf(stderr, "Report bugs to tinc@tinc-vpn.org.\n");
}

static struct option const long_options[] = {
	{"help", no_argument, NULL, 1},
	{NULL, 0, NULL, 0}
};

int main(int argc, char *argv[]) {
	program_name = argv[0];
	int r;
	int option_index = 0;

	while((r = getopt_long(argc, argv, "", long_options, &option_index)) != EOF) {
		switch(r) {
		case 0:   /* long option */
			break;

		case '?': /* wrong options */
			usage();
			return 1;

		case 1: /* help */
			usage();
			return 0;

		default:
			break;
		}
	}

	argc -= optind - 1;
	argv += optind - 1;

	if(argc != 3) {
		fprintf(stderr, "Wrong number of arguments.\n");
		usage();
		return 1;
	}

	crypto_init();

	ecdsa_t *key = ecdsa_generate();

	if(!key) {
		return 1;
	}

	FILE *fp = fopen(argv[1], "w");

	if(fp) {
		if(!ecdsa_write_pem_private_key(key, fp)) {
			fprintf(stderr, "Could not write ECDSA private key\n");
			return 1;
		}

		fclose(fp);
	} else {
		fprintf(stderr, "Could not open '%s' for writing: %s\n", argv[1], strerror(errno));
		return 1;
	}

	fp = fopen(argv[2], "w");

	if(fp) {
		if(!ecdsa_write_pem_public_key(key, fp)) {
			fprintf(stderr, "Could not write ECDSA public key\n");
		}

		fclose(fp);
	} else {
		fprintf(stderr, "Could not open '%s' for writing: %s\n", argv[2], strerror(errno));
		return 1;
	}

	return 0;
}
