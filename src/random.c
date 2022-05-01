#include "system.h"

#include "random.h"

#ifndef HAVE_GETENTROPY
static int random_fd = -1;
#endif

void random_init(void) {
#ifndef HAVE_GETENTROPY
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
#ifndef HAVE_GETENTROPY
	close(random_fd);
#endif
}

void randomize(void *vout, size_t outlen) {
	uint8_t *out = vout;

	while(outlen) {
#ifdef HAVE_GETENTROPY
		int reqlen = (int) MIN(256, outlen);
		int len = !getentropy(out, reqlen) ? reqlen : -1;
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
