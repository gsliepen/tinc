#include "system.h"

#include "random.h"

#ifndef HAVE_GETRANDOM
static int random_fd = -1;
#endif

void random_init(void) {
#ifndef HAVE_GETRANDOM
	random_fd = open("/dev/urandom", O_RDONLY);

	if(random_fd < 0) {
		random_fd = open("/dev/random", O_RDONLY);
	}

	if(random_fd < 0) {
		fprintf(stderr, "Could not open source of random numbers: %s\n", strerror(errno));
		abort();
	}

#endif
}

void random_exit(void) {
#ifndef HAVE_GETRANDOM
	close(random_fd);
#endif
}

void randomize(void *vout, size_t outlen) {
	uint8_t *out = vout;

	while(outlen) {
#ifdef HAVE_GETRANDOM
		ssize_t len = getrandom(out, outlen, 0);
#else
		ssize_t len = read(random_fd, out, outlen);
#endif

		if(len <= 0) {
			if(len == -1 && (errno == EAGAIN || errno == EINTR)) {
				continue;
			}

			fprintf(stderr, "Could not read random numbers: %s\n", strerror(errno));
			abort();
		}

		out += len;
		outlen -= len;
	}
}
