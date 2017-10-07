/*
    sptps_speed.c -- SPTPS benchmark
    Copyright (C) 2013-2014 Guus Sliepen <guus@tinc-vpn.org>

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
#include "utils.h"

#include <poll.h>

#include "crypto.h"
#include "ecdh.h"
#include "ecdsa.h"
#include "ecdsagen.h"
#include "sptps.h"

// Symbols necessary to link with logger.o
bool send_request(void *c, const char *msg, ...) {
	return false;
}
struct list_t *connection_list = NULL;
bool send_meta(void *c, const char *msg, int len) {
	return false;
}
char *logfilename = NULL;
bool do_detach = false;
struct timeval now;

static bool send_data(void *handle, uint8_t type, const void *data, size_t len) {
	int fd = *(int *)handle;
	send(fd, data, len, 0);
	return true;
}

static bool receive_record(void *handle, uint8_t type, const void *data, uint16_t len) {
	return true;
}

static void receive_data(sptps_t *sptps) {
	char buf[4096], *bufp = buf;
	int fd = *(int *)sptps->handle;
	size_t len = recv(fd, buf, sizeof(buf), 0);

	while(len) {
		size_t done = sptps_receive_data(sptps, bufp, len);

		if(!done) {
			abort();
		}

		bufp += done;
		len -= done;
	}
}

struct timespec start;
struct timespec end;
double elapsed;
double rate;
unsigned int count;

static void clock_start() {
	count = 0;
	clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &start);
}

static bool clock_countto(double seconds) {
	clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &end);
	elapsed = end.tv_sec + end.tv_nsec * 1e-9 - start.tv_sec - start.tv_nsec * 1e-9;

	if(elapsed < seconds) {
		return ++count;
	}

	rate = count / elapsed;
	return false;
}

int main(int argc, char *argv[]) {
	ecdsa_t *key1, *key2;
	ecdh_t *ecdh1, *ecdh2;
	sptps_t sptps1, sptps2;
	char buf1[4096], buf2[4096], buf3[4096];
	double duration = argc > 1 ? atof(argv[1]) : 10;

	crypto_init();

	randomize(buf1, sizeof(buf1));
	randomize(buf2, sizeof(buf2));
	randomize(buf3, sizeof(buf3));

	// Key generation

	fprintf(stderr, "Generating keys for %lg seconds: ", duration);

	for(clock_start(); clock_countto(duration);) {
		ecdsa_free(ecdsa_generate());
	}

	fprintf(stderr, "%17.2lf op/s\n", rate);

	key1 = ecdsa_generate();
	key2 = ecdsa_generate();

	// Ed25519 signatures

	fprintf(stderr, "Ed25519 sign for %lg seconds: ", duration);

	for(clock_start(); clock_countto(duration);)
		if(!ecdsa_sign(key1, buf1, 256, buf2)) {
			return 1;
		}

	fprintf(stderr, "%20.2lf op/s\n", rate);

	fprintf(stderr, "Ed25519 verify for %lg seconds: ", duration);

	for(clock_start(); clock_countto(duration);)
		if(!ecdsa_verify(key1, buf1, 256, buf2)) {
			fprintf(stderr, "Signature verification failed\n");
			return 1;
		}

	fprintf(stderr, "%18.2lf op/s\n", rate);

	ecdh1 = ecdh_generate_public(buf1);
	fprintf(stderr, "ECDH for %lg seconds: ", duration);

	for(clock_start(); clock_countto(duration);) {
		ecdh2 = ecdh_generate_public(buf2);

		if(!ecdh2) {
			return 1;
		}

		if(!ecdh_compute_shared(ecdh2, buf1, buf3)) {
			return 1;
		}
	}

	fprintf(stderr, "%28.2lf op/s\n", rate);
	ecdh_free(ecdh1);

	// SPTPS authentication phase

	int fd[2];

	if(socketpair(AF_UNIX, SOCK_STREAM, 0, fd)) {
		fprintf(stderr, "Could not create a UNIX socket pair: %s\n", sockstrerror(sockerrno));
		return 1;
	}

	struct pollfd pfd[2] = {{fd[0], POLLIN}, {fd[1], POLLIN}};

	fprintf(stderr, "SPTPS/TCP authenticate for %lg seconds: ", duration);

	for(clock_start(); clock_countto(duration);) {
		sptps_start(&sptps1, fd + 0, true, false, key1, key2, "sptps_speed", 11, send_data, receive_record);
		sptps_start(&sptps2, fd + 1, false, false, key2, key1, "sptps_speed", 11, send_data, receive_record);

		while(poll(pfd, 2, 0)) {
			if(pfd[0].revents) {
				receive_data(&sptps1);
			}

			if(pfd[1].revents) {
				receive_data(&sptps2);
			}
		}

		sptps_stop(&sptps1);
		sptps_stop(&sptps2);
	}

	fprintf(stderr, "%10.2lf op/s\n", rate * 2);

	// SPTPS data

	sptps_start(&sptps1, fd + 0, true, false, key1, key2, "sptps_speed", 11, send_data, receive_record);
	sptps_start(&sptps2, fd + 1, false, false, key2, key1, "sptps_speed", 11, send_data, receive_record);

	while(poll(pfd, 2, 0)) {
		if(pfd[0].revents) {
			receive_data(&sptps1);
		}

		if(pfd[1].revents) {
			receive_data(&sptps2);
		}
	}

	fprintf(stderr, "SPTPS/TCP transmit for %lg seconds: ", duration);

	for(clock_start(); clock_countto(duration);) {
		if(!sptps_send_record(&sptps1, 0, buf1, 1451)) {
			abort();
		}

		receive_data(&sptps2);
	}

	rate *= 2 * 1451 * 8;

	if(rate > 1e9) {
		fprintf(stderr, "%14.2lf Gbit/s\n", rate / 1e9);
	} else if(rate > 1e6) {
		fprintf(stderr, "%14.2lf Mbit/s\n", rate / 1e6);
	} else if(rate > 1e3) {
		fprintf(stderr, "%14.2lf kbit/s\n", rate / 1e3);
	}

	sptps_stop(&sptps1);
	sptps_stop(&sptps2);

	// SPTPS datagram authentication phase

	close(fd[0]);
	close(fd[1]);

	if(socketpair(AF_UNIX, SOCK_DGRAM, 0, fd)) {
		fprintf(stderr, "Could not create a UNIX socket pair: %s\n", sockstrerror(sockerrno));
		return 1;
	}

	fprintf(stderr, "SPTPS/UDP authenticate for %lg seconds: ", duration);

	for(clock_start(); clock_countto(duration);) {
		sptps_start(&sptps1, fd + 0, true, true, key1, key2, "sptps_speed", 11, send_data, receive_record);
		sptps_start(&sptps2, fd + 1, false, true, key2, key1, "sptps_speed", 11, send_data, receive_record);

		while(poll(pfd, 2, 0)) {
			if(pfd[0].revents) {
				receive_data(&sptps1);
			}

			if(pfd[1].revents) {
				receive_data(&sptps2);
			}
		}

		sptps_stop(&sptps1);
		sptps_stop(&sptps2);
	}

	fprintf(stderr, "%10.2lf op/s\n", rate * 2);

	// SPTPS datagram data

	sptps_start(&sptps1, fd + 0, true, true, key1, key2, "sptps_speed", 11, send_data, receive_record);
	sptps_start(&sptps2, fd + 1, false, true, key2, key1, "sptps_speed", 11, send_data, receive_record);

	while(poll(pfd, 2, 0)) {
		if(pfd[0].revents) {
			receive_data(&sptps1);
		}

		if(pfd[1].revents) {
			receive_data(&sptps2);
		}
	}

	fprintf(stderr, "SPTPS/UDP transmit for %lg seconds: ", duration);

	for(clock_start(); clock_countto(duration);) {
		if(!sptps_send_record(&sptps1, 0, buf1, 1451)) {
			abort();
		}

		receive_data(&sptps2);
	}

	rate *= 2 * 1451 * 8;

	if(rate > 1e9) {
		fprintf(stderr, "%14.2lf Gbit/s\n", rate / 1e9);
	} else if(rate > 1e6) {
		fprintf(stderr, "%14.2lf Mbit/s\n", rate / 1e6);
	} else if(rate > 1e3) {
		fprintf(stderr, "%14.2lf kbit/s\n", rate / 1e3);
	}

	sptps_stop(&sptps1);
	sptps_stop(&sptps2);

	// Clean up

	close(fd[0]);
	close(fd[1]);
	ecdsa_free(key1);
	ecdsa_free(key2);
	crypto_exit();

	return 0;
}
