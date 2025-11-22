#include "system.h"

#include <assert.h>

#include "cpu.h"

#define CPUID_ECX_SSSE3   0x00000200
#define CPUID_EBX_AVX2    0x00000020

#define CPU_INFO_LEN 4

static uint16_t features;

// Copyright (c) 2014-2021 Frank Denis
static void tinc_cpuid(unsigned int cpu_info[CPU_INFO_LEN], const unsigned int cpu_info_type) {
	memset(cpu_info, 0, CPU_INFO_LEN * sizeof(*cpu_info));

#if defined(_MSC_VER) && (defined(_M_X64) || defined(_M_AMD64) || defined(_M_IX86))
	__cpuid((int *) cpu_info, cpu_info_type);
#elif defined(HAVE_CPUID)
#  if defined(__x86_64__)
	__asm__ __volatile__("xchgq %%rbx, %q1; cpuid; xchgq %%rbx, %q1"
	                     : "=a"(cpu_info[0]), "=&r"(cpu_info[1]),
	                     "=c"(cpu_info[2]), "=d"(cpu_info[3])
	                     : "0"(cpu_info_type), "2"(0U));
#  elif defined(__i386__)
	__asm__ __volatile__(
	        "pushfl; pushfl; "
	        "popl %0; "
	        "movl %0, %1; xorl %2, %0; "
	        "pushl %0; "
	        "popfl; pushfl; popl %0; popfl"
	        : "=&r"(cpu_info[0]), "=&r"(cpu_info[1])
	        : "i"(0x200000));

	if(((cpu_info[0] ^ cpu_info[1]) & 0x200000) == 0x0) {
		return;
	}

	__asm__ __volatile__("xchgl %%ebx, %k1; cpuid; xchgl %%ebx, %k1"
	                     : "=a"(cpu_info[0]), "=&r"(cpu_info[1]),
	                     "=c"(cpu_info[2]), "=d"(cpu_info[3])
	                     : "0"(cpu_info_type), "2"(0U));
#  else
	__asm__ __volatile__("cpuid"
	                     : "=a"(cpu_info[0]), "=b"(cpu_info[1]),
	                     "=c"(cpu_info[2]), "=d"(cpu_info[3])
	                     : "0"(cpu_info_type), "2"(0U));
#  endif
#else
	(void)cpu_info_type;
#endif
}

static bool initialized;

void cpu_detect_features(void) {
	initialized = true;

	unsigned int cpu_info[CPU_INFO_LEN];
	tinc_cpuid(cpu_info, 0x00);

	if(!cpu_info[0]) {
		return;
	}

#ifdef HAVE_CPU_SSSE3
	tinc_cpuid(cpu_info, 0x01);

	if(cpu_info[2] & CPUID_ECX_SSSE3) {
		features |= CPU_SSSE3;
	}

#endif

#ifdef HAVE_CPU_AVX2
	tinc_cpuid(cpu_info, 0x07);

	if(cpu_info[1] & CPUID_EBX_AVX2) {
		features |= CPU_AVX2;
	}

#endif
}

bool cpu_supports(cpu_feature_t feat) {
	assert(initialized);
	return features & feat;
}
