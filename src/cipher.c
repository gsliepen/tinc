#include "cipher.h"
#include "xalloc.h"

#ifndef DISABLE_LEGACY

cipher_t *cipher_alloc() {
	return xzalloc(sizeof(cipher_t));
}

void cipher_free(cipher_t **cipher) {
	if(cipher && *cipher) {
		cipher_close(*cipher);
		free(*cipher);
		*cipher = NULL;
	}
}

#endif // DISABLE_LEGACY
