#ifndef TINC_BENCHMARK_H
#define TINC_BENCHMARK_H

#include "system.h"

static struct timespec start;
static struct timespec end;
static double elapsed;
static double rate;
static unsigned int count;

static void clock_start(void) {
	count = 0;
	clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &start);
}

static bool clock_countto(double seconds) {
	clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &end);
	elapsed = (double) end.tv_sec + (double) end.tv_nsec * 1e-9
	          - (double) start.tv_sec - (double) start.tv_nsec * 1e-9;

	if(elapsed < seconds) {
		return ++count;
	}

	rate = count / elapsed;
	return false;
}

#endif // TINC_BENCHMARK_H
