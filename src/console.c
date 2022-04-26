#include "system.h"

#include "console.h"

bool use_ansi_escapes(FILE *out) {
	bool is_tty = isatty(fileno(out));

#ifndef HAVE_WINDOWS
	const char *term = getenv("TERM");
	return is_tty && term && strcmp(term, "dumb");
#else
	HANDLE console;

	if(out == stdout) {
		console = GetStdHandle(STD_OUTPUT_HANDLE);
	} else if(out == stderr) {
		console = GetStdHandle(STD_ERROR_HANDLE);
	} else {
		return false;
	}

	DWORD mode = 0;
	return is_tty &&
	       console != INVALID_HANDLE_VALUE &&
	       GetConsoleMode(console, &mode) &&
	       SetConsoleMode(console, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
#endif
}
