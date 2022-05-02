#include "../system.h"

#include <gcrypt.h>

#include "../crypto.h"

void crypto_init(void) {
	gcry_control(GCRYCTL_INIT_SECMEM, 32 * 1024, 0);
	gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);
}
