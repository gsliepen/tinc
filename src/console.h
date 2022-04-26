#ifndef TINC_CONSOLE_H
#define TINC_CONSOLE_H

#include "system.h"

// true if stderr supports ANSI escape sequences.
extern bool use_ansi_escapes(FILE *out);

#endif // TINC_CONSOLE_H
