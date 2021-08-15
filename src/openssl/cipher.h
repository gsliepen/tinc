#ifndef TINC_OPENSSL_CIPHER_H
#define TINC_OPENSSL_CIPHER_H

#include <openssl/evp.h>

struct cipher {
	EVP_CIPHER_CTX *ctx;
	const EVP_CIPHER *cipher;
};

#endif
