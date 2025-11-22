#include "../system.h"

#include "chacha.h"
#include "../xalloc.h"

#if defined(__clang__)
#  pragma clang attribute push (__attribute__((target("sse2,ssse3"))), apply_to=function)
#elif defined(__GNUC__)
#  pragma GCC target("sse2", "ssse3")
#endif

#include <immintrin.h>

void chacha_encrypt_bytes_ssse3(chacha_ctx *ctx, const uint8_t *m, uint8_t *c, uint32_t bytes) {
	uint32_t *x = &ctx->input[0];

	if(!bytes) {
		return;
	}

#include "chacha_ssse3.h"
}

#ifdef __clang__
#  pragma clang attribute pop
#endif
