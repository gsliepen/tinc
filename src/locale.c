#include <locale.h>
#include "locale.h"
#include "lib/gettext.h"

bool init_locale() {
	if(!setlocale(LC_ALL, "")) {
		fprintf(stderr, "Could not set locale.\n");
		return false;
	}

	if(!bindtextdomain(PACKAGE, LOCALEDIR)) {
		fprintf(stderr, "Could not bind text domain: %s.\n", strerror(errno));
		return false;
	}

	if(!textdomain(PACKAGE)) {
		fprintf(stderr, "Could not set text domain: %s.\n", strerror(errno));
		return false;
	}

	return true;
}
