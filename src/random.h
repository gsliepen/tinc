#ifndef TINC_RANDOM_H
#define TINC_RANDOM_H

#include "system.h"

extern void random_init(void);
extern void random_exit(void);
extern void randomize(void *vout, size_t outlen);

#endif // TINC_RANDOM_H
