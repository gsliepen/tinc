#include "../system.h"

#include <wincrypt.h>

#include "../random.h"

static HCRYPTPROV prov;

void random_init(void) {
	if(!CryptAcquireContext(&prov, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
		fprintf(stderr, "CryptAcquireContext() failed!\n");
		abort();
	}
}

void random_exit(void) {
	CryptReleaseContext(prov, 0);
}

void randomize(void *vout, size_t outlen) {
	if(!CryptGenRandom(prov, outlen, vout)) {
		fprintf(stderr, "CryptGenRandom() failed\n");
		abort();
	}
}
