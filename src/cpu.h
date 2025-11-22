#ifndef TINC_CPU_H
#define TINC_CPU_H

#include "system.h"

typedef enum {
	CPU_AVX2  = 1 << 0,
	CPU_SSSE3 = 1 << 1,
} cpu_feature_t;

// Detect supported features. Should be called once at application startup.
void cpu_detect_features(void);

// Check if current CPU supports feature
bool cpu_supports(cpu_feature_t feat);

#endif // TINC_CPU_H
