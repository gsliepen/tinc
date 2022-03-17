#include <openssl/err.h>
#include "log.h"
#include "../logger.h"

void openssl_err(const char *msg) {
	const char *err = ERR_error_string(ERR_peek_last_error(), NULL);
	logger(DEBUG_ALWAYS, LOG_ERR, "OpenSSL error: unable to %s: %s", msg, err);
}
