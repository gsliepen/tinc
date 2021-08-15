#include "digest.h"
#include "xalloc.h"

#ifndef DISABLE_LEGACY

digest_t *digest_alloc() {
	return xzalloc(sizeof(digest_t));
}

void digest_free(digest_t **digest) {
	if(digest && *digest) {
		digest_close(*digest);
		free(*digest);
		*digest = NULL;
	}
}

#endif // DISABLE_LEGACY
