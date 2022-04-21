#include "system.h"

#include "pidfile.h"
#include "names.h"

pidfile_t *read_pidfile(void) {
	FILE *f = fopen(pidfilename, "r");

	if(!f) {
		return NULL;
	}

	pidfile_t *pf = malloc(sizeof(pidfile_t));
	int read = fscanf(f, "%20d %64s %128s port %128s", &pf->pid, pf->cookie, pf->host, pf->port);
	fclose(f);

	if(read != 4) {
		free(pf);
		pf = NULL;
	}

	return pf;
}


bool write_pidfile(const char *controlcookie, const char *address) {
	const mode_t mask = umask(0);
	umask(mask | 077);
	FILE *f = fopen(pidfilename, "w");

	if(!f) {
		return false;
	}

	umask(mask);
	fprintf(f, "%d %s %s\n", (int)getpid(), controlcookie, address);
	return !fclose(f);
}
