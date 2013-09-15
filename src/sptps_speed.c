/*
    sptps_speed.c -- SPTPS benchmark
    Copyright (C) 2013 Guus Sliepen <guus@tinc-vpn.org>,

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

#include <poll.h>

#include "crypto.h"
#include "ecdh.h"
#include "ecdsa.h"
#include "ecdsagen.h"
#include "sptps.h"

// Symbols necessary to link with logger.o
bool send_request(void *c, const char *msg, ...) { return false; }
struct list_t *connection_list = NULL;
bool send_meta(void *c, const char *msg , int len) { return false; }
char *logfilename = NULL;
struct timeval now;

static bool send_data(void *handle, uint8_t type, const char *data, size_t len) {
	int fd = *(int *)handle;
	send(fd, data, len, 0);
	return true;
}

static bool receive_record(void *handle, uint8_t type, const char *data, uint16_t len) {
	return true;
}

static void receive_data(sptps_t *sptps) {
	char buf[4096];
	int fd = *(int *)sptps->handle;
	size_t len = recv(fd, buf, sizeof buf, 0);
	sptps_receive_data(sptps, buf, len);
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

static bool clock_countto(int seconds) {
	clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &end);
	elapsed = end.tv_sec + end.tv_nsec * 1e-9 - start.tv_sec - start.tv_nsec * 1e-9;
	if(elapsed < seconds)
		return ++count;
		
	rate = count / elapsed;
	return false;
}

int main(int argc, char *argv[]) {
	ecdsa_t *key1, *key2;
	ecdh_t *ecdh1, *ecdh2;
	sptps_t sptps1, sptps2;
	char buf1[4096], buf2[4096], buf3[4096];

	crypto_init();

	// Key generation

	fprintf(stderr, "Generating keys for 10 seconds: ");
	for(clock_start(); clock_countto(10);)
		key1 = ecdsa_generate();
	fprintf(stderr, "%13.2lf op/s\n", rate);

	// ECDSA signatures

	fprintf(stderr, "ECDSA sign for 10 seconds: ");
	for(clock_start(); clock_countto(10);)
		ecdsa_sign(key1, buf1, 256, buf2);
	fprintf(stderr, "%18.2lf op/s\n", rate);
	
	fprintf(stderr, "ECDSA verify for 10 seconds: ");
	for(clock_start(); clock_countto(10);)
		ecdsa_verify(key1, buf1, 256, buf2);
	fprintf(stderr, "%16.2lf op/s\n", rate);

	ecdh1 = ecdh_generate_public(buf1);
	fprintf(stderr, "ECDH for 10 seconds: ");
	for(clock_start(); clock_countto(10);) {
		ecdh2 = ecdh_generate_public(buf2);
		ecdh_compute_shared(ecdh2, buf1, buf3);
	}
	fprintf(stderr, "%24.2lf op/s\n", rate);
	ecdh_free(ecdh1);

	// SPTPS authentication phase

	key2 = ecdsa_generate();

	int fd[2];
	if(socketpair(AF_UNIX, SOCK_STREAM, 0, fd)) {
		fprintf(stderr, "Could not create a UNIX socket pair: %s\n", strerror(errno));
		return 1;
	}

	struct pollfd pfd[2] = {{fd[0], POLLIN}, {fd[1], POLLIN}};

	fprintf(stderr, "SPTPS authenticate for 10 seconds: ");
	for(clock_start(); clock_countto(10);) {
		sptps_start(&sptps1, fd + 0, true, false, key1, key2, "sptps_speed", 11, send_data, receive_record);
		sptps_start(&sptps2, fd + 1, false, false, key2, key1, "sptps_speed", 11, send_data, receive_record);
		while(poll(pfd, 2, 0)) {
			if(pfd[0].revents)
				receive_data(&sptps1);
			if(pfd[1].revents)
				receive_data(&sptps2);
		}
		sptps_stop(&sptps1);
		sptps_stop(&sptps2);
	} 
	fprintf(stderr, "%10.2lf op/s\n", rate * 2);	

	// SPTPS data

	sptps_start(&sptps1, fd + 0, true, false, key1, key2, "sptps_speed", 11, send_data, receive_record);
	sptps_start(&sptps2, fd + 1, false, false, key2, key1, "sptps_speed", 11, send_data, receive_record);
	while(poll(pfd, 2, 0)) {
		if(pfd[0].revents)
			receive_data(&sptps1);
		if(pfd[1].revents)
			receive_data(&sptps2);
	}
	fprintf(stderr, "SPTPS transmit for 10 seconds: ");
	for(clock_start(); clock_countto(10);) {
		sptps_send_record(&sptps1, 0, buf1, 1451);
		receive_data(&sptps2);
	}
	rate *= 2 * 1451 * 8;
	if(rate > 1e9)
		fprintf(stderr, "%14.2lf Gbit/s\n", rate / 1e9);
	else if(rate > 1e6)
		fprintf(stderr, "%14.2lf Mbit/s\n", rate / 1e6);
	else if(rate > 1e3)
		fprintf(stderr, "%14.2lf kbit/s\n", rate / 1e3);
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
