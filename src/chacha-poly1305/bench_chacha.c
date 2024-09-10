#include "../system.h"

#include "../benchmark.h"
#include "../random.h"
#include "../crypto.h"
#include "../xalloc.h"
#include "chacha.h"

#define BUFFER_SIZE (1024 * 1024)

static FILE *dev_null;

static void benchmark(chacha_ctx *ctx, const uint8_t *plaintext, uint8_t *ciphertext, size_t len) {
	for(clock_start(); clock_countto(5);) {
		chacha_encrypt_bytes(ctx, plaintext, ciphertext, len);
	}

	// Prevent the compiler from optimizing out encryption
	fwrite(ciphertext, len, 1, dev_null);
	fprintf(stderr, "%8zu: %14.2lf op/s\n", len, rate);
}

const size_t block_sizes[] = {
	32,
	256,
	512,
	1024,
	16 * 1024,
	128 * 1024,
	BUFFER_SIZE,
};

int main(void) {
	dev_null = fopen("/dev/null", "w");
	random_init();
	chacha_resolve_functions();

	uint8_t key[256 / 8];
	uint8_t iv[8];
	randomize(key, sizeof(key));
	randomize(iv, sizeof(iv));

	chacha_ctx ctx;
	chacha_keysetup(&ctx, key, 256);
	chacha_ivsetup(&ctx, iv, NULL);

	uint8_t *plaintext = xmalloc(BUFFER_SIZE);
	uint8_t *ciphertext = malloc(BUFFER_SIZE);
	randomize(plaintext, BUFFER_SIZE);

	for(size_t i = 0; i < sizeof(block_sizes) / sizeof(*block_sizes); ++i) {
		benchmark(&ctx, plaintext, ciphertext, block_sizes[i]);
	}

	free(ciphertext);
	free(plaintext);
	random_exit();
	fclose(dev_null);

	return 0;
}
