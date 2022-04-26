/*
    sptps_test.c -- Simple Peer-to-Peer Security test program
    Copyright (C) 2011-2022 Guus Sliepen <guus@tinc-vpn.org>,

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

#include "crypto.h"
#include "random.h"
#include "ecdsagen.h"
#include "logger.h"
#include "names.h"

void logger(debug_t level, int priority, const char *format, ...) {
	(void)level;
	(void)priority;
	va_list ap;

	va_start(ap, format);
	vfprintf(stderr, format, ap);
	va_end(ap);

	fputc('\n', stderr);
}

static void usage(void) {
	fprintf(stderr, "Usage: %s [options] private_key_file public_key_file\n\n", program_name);
	fprintf(stderr, "Valid options are:\n"
	        "  --help  Display this help and exit.\n"
	        "\n");
	fprintf(stderr, "Report bugs to tinc@tinc-vpn.org.\n");
}

typedef enum option_t {
	OPT_BAD_OPTION  = '?',
	OPT_LONG_OPTION =  0,

	OPT_HELP        = 255,
} option_t;

static struct option const long_options[] = {
	{"help", no_argument, NULL, OPT_HELP},
	{NULL,   0,           NULL, 0}
};

static int generate_keypair(char *argv[]) {
	ecdsa_t *key = ecdsa_generate();

	if(!key) {
		return 1;
	}

	FILE *fp = fopen(argv[1], "w");

	if(fp) {
		if(!ecdsa_write_pem_private_key(key, fp)) {
			fprintf(stderr, "Could not write ECDSA private key\n");
			ecdsa_free(key);
			return 1;
		}

		fclose(fp);
	} else {
		fprintf(stderr, "Could not open '%s' for writing: %s\n", argv[1], strerror(errno));
		ecdsa_free(key);
		return 1;
	}

	fp = fopen(argv[2], "w");

	if(fp) {
		if(!ecdsa_write_pem_public_key(key, fp)) {
			fprintf(stderr, "Could not write ECDSA public key\n");
		}

		ecdsa_free(key);
		fclose(fp);
		return 0;
	} else {
		fprintf(stderr, "Could not open '%s' for writing: %s\n", argv[2], strerror(errno));
		ecdsa_free(key);
		return 1;
	}
}

int main(int argc, char *argv[]) {
	program_name = argv[0];
	int r;
	int option_index = 0;

	while((r = getopt_long(argc, argv, "", long_options, &option_index)) != EOF) {
		switch((option_t) r) {
		case OPT_LONG_OPTION:
			break;

		case OPT_BAD_OPTION:
			usage();
			return 1;

		case OPT_HELP:
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

	random_init();
	crypto_init();

	int result = generate_keypair(argv);

	random_exit();

	return result;
}
