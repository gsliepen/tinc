/*
    conf.c -- configuration code
    Copyright (C) 1998 Robert van der Meulen
                  1998-2003 Ivo Timmermans <ivo@o2w.nl>
                  2000-2003 Guus Sliepen <guus@sliepen.eu.org>
		  2000 Cris van Pelt <tribbel@arise.dhs.org>

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.

    $Id: conf.c,v 1.9.4.68 2003/07/22 20:55:19 guus Exp $
*/

#include "system.h"

#include "avl_tree.h"
#include "conf.h"
#include "logger.h"
#include "netutl.h"				/* for str2address */
#include "utils.h"				/* for cp */
#include "xalloc.h"

avl_tree_t *config_tree;

int pingtimeout = 0;			/* seconds before timeout */
char *confbase = NULL;			/* directory in which all config files are */
char *netname = NULL;			/* name of the vpn network */

static int config_compare(config_t *a, config_t *b)
{
	int result;

	result = strcasecmp(a->variable, b->variable);

	if(result)
		return result;

	result = a->line - b->line;

	if(result)
		return result;
	else
		return strcmp(a->file, b->file);
}

void init_configuration(avl_tree_t ** config_tree)
{
	cp();

	*config_tree = avl_alloc_tree((avl_compare_t) config_compare, (avl_action_t) free_config);
}

void exit_configuration(avl_tree_t ** config_tree)
{
	cp();

	avl_delete_tree(*config_tree);
	*config_tree = NULL;
}

config_t *new_config(void)
{
	cp();

	return (config_t *) xmalloc_and_zero(sizeof(config_t));
}

void free_config(config_t *cfg)
{
	cp();

	if(cfg->variable)
		free(cfg->variable);

	if(cfg->value)
		free(cfg->value);

	if(cfg->file)
		free(cfg->file);

	free(cfg);
}

void config_add(avl_tree_t *config_tree, config_t *cfg)
{
	cp();

	avl_insert(config_tree, cfg);
}

config_t *lookup_config(avl_tree_t *config_tree, char *variable)
{
	config_t cfg, *found;

	cp();

	cfg.variable = variable;
	cfg.file = "";
	cfg.line = 0;

	found = avl_search_closest_greater(config_tree, &cfg);

	if(!found)
		return NULL;

	if(strcasecmp(found->variable, variable))
		return NULL;

	return found;
}

config_t *lookup_config_next(avl_tree_t *config_tree, config_t *cfg)
{
	avl_node_t *node;
	config_t *found;

	cp();

	node = avl_search_node(config_tree, cfg);

	if(node) {
		if(node->next) {
			found = (config_t *) node->next->data;

			if(!strcasecmp(found->variable, cfg->variable))
				return found;
		}
	}

	return NULL;
}

bool get_config_bool(config_t *cfg, bool *result)
{
	cp();

	if(!cfg)
		return false;

	if(!strcasecmp(cfg->value, "yes")) {
		*result = true;
		return true;
	} else if(!strcasecmp(cfg->value, "no")) {
		*result = false;
		return true;
	}

	logger(LOG_ERR, _("\"yes\" or \"no\" expected for configuration variable %s in %s line %d"),
		   cfg->variable, cfg->file, cfg->line);

	return false;
}

bool get_config_int(config_t *cfg, int *result)
{
	cp();

	if(!cfg)
		return false;

	if(sscanf(cfg->value, "%d", result) == 1)
		return true;

	logger(LOG_ERR, _("Integer expected for configuration variable %s in %s line %d"),
		   cfg->variable, cfg->file, cfg->line);

	return false;
}

bool get_config_string(config_t *cfg, char **result)
{
	cp();

	if(!cfg)
		return false;

	*result = xstrdup(cfg->value);

	return true;
}

bool get_config_address(config_t *cfg, struct addrinfo **result)
{
	struct addrinfo *ai;

	cp();

	if(!cfg)
		return false;

	ai = str2addrinfo(cfg->value, NULL, 0);

	if(ai) {
		*result = ai;
		return true;
	}

	logger(LOG_ERR, _("Hostname or IP address expected for configuration variable %s in %s line %d"),
		   cfg->variable, cfg->file, cfg->line);

	return false;
}

bool get_config_subnet(config_t *cfg, subnet_t ** result)
{
	subnet_t *subnet;

	cp();

	if(!cfg)
		return false;

	subnet = str2net(cfg->value);

	if(!subnet) {
		logger(LOG_ERR, _("Subnet expected for configuration variable %s in %s line %d"),
			   cfg->variable, cfg->file, cfg->line);
		return false;
	}

	/* Teach newbies what subnets are... */

	if(((subnet->type == SUBNET_IPV4)
		&& !maskcheck(&subnet->net.ipv4.address, subnet->net.ipv4.prefixlength, sizeof(ipv4_t)))
		|| ((subnet->type == SUBNET_IPV6)
		&& !maskcheck(&subnet->net.ipv6.address, subnet->net.ipv6.prefixlength, sizeof(ipv6_t)))) {
		logger(LOG_ERR, _ ("Network address and prefix length do not match for configuration variable %s in %s line %d"),
			   cfg->variable, cfg->file, cfg->line);
		free(subnet);
		return false;
	}

	*result = subnet;

	return true;
}

/*
  Read exactly one line and strip the trailing newline if any.  If the
  file was on EOF, return NULL. Otherwise, return all the data in a
  dynamically allocated buffer.

  If line is non-NULL, it will be used as an initial buffer, to avoid
  unnecessary mallocing each time this function is called.  If buf is
  given, and buf needs to be expanded, the var pointed to by buflen
  will be increased.
*/
static char *readline(FILE * fp, char **buf, size_t *buflen)
{
	char *newline = NULL;
	char *p;
	char *line;					/* The array that contains everything that has been read so far */
	char *idx;					/* Read into this pointer, which points to an offset within line */
	size_t size, newsize;		/* The size of the current array pointed to by line */
	size_t maxlen;				/* Maximum number of characters that may be read with fgets.  This is newsize - oldsize. */

	if(feof(fp))
		return NULL;

	if(buf && buflen) {
		size = *buflen;
		line = *buf;
	} else {
		size = 100;
		line = xmalloc(size);
	}

	maxlen = size;
	idx = line;
	*idx = 0;

	for(;;) {
		errno = 0;
		p = fgets(idx, maxlen, fp);

		if(!p) {				/* EOF or error */
			if(feof(fp))
				break;

			/* otherwise: error; let the calling function print an error message if applicable */
			free(line);
			return NULL;
		}

		newline = strchr(p, '\n');

		if(!newline) {			/* We haven't yet read everything to the end of the line */
			newsize = size << 1;
			line = xrealloc(line, newsize);
			idx = &line[size - 1];
			maxlen = newsize - size + 1;
			size = newsize;
		} else {
			*newline = '\0';	/* kill newline */
			break;				/* yay */
		}
	}

	if(buf && buflen) {
		*buflen = size;
		*buf = line;
	}

	return line;
}

/*
  Parse a configuration file and put the results in the configuration tree
  starting at *base.
*/
int read_config_file(avl_tree_t *config_tree, const char *fname)
{
	int err = -2;				/* Parse error */
	FILE *fp;
	char *buffer, *line;
	char *variable, *value;
	int lineno = 0;
	bool ignore = false;
	config_t *cfg;
	size_t bufsize;

	cp();

	fp = fopen(fname, "r");

	if(!fp) {
		logger(LOG_ERR, _("Cannot open config file %s: %s"), fname,
			   strerror(errno));
		return -3;
	}

	bufsize = 100;
	buffer = xmalloc(bufsize);

	for(;;) {
		line = readline(fp, &buffer, &bufsize);

		if(!line) {
			err = -1;
			break;
		}

		if(feof(fp)) {
			err = 0;
			break;
		}

		lineno++;

		variable = strtok(line, "\t =");

		if(!variable)
			continue;			/* no tokens on this line */

		if(variable[0] == '#')
			continue;			/* comment: ignore */

		if(!strcmp(variable, "-----BEGIN"))
			ignore = true;

		if(!ignore) {
			value = strtok(NULL, "\t\n\r =");

			if(!value || value[0] == '#') {
				logger(LOG_ERR, _("No value for variable `%s' on line %d while reading config file %s"),
					   variable, lineno, fname);
				break;
			}

			cfg = new_config();
			cfg->variable = xstrdup(variable);
			cfg->value = xstrdup(value);
			cfg->file = xstrdup(fname);
			cfg->line = lineno;

			config_add(config_tree, cfg);
		}

		if(!strcmp(variable, "-----END"))
			ignore = false;
	}

	free(buffer);
	fclose(fp);

	return err;
}

bool read_server_config()
{
	char *fname;
	int x;

	cp();

	asprintf(&fname, "%s/tinc.conf", confbase);
	x = read_config_file(config_tree, fname);

	if(x == -1) {				/* System error: complain */
		logger(LOG_ERR, _("Failed to read `%s': %s"), fname, strerror(errno));
	}

	free(fname);

	return x == 0;
}

bool is_safe_path(const char *file)
{
#if !(defined(HAVE_CYGWIN) || defined(HAVE_MINGW))
	char *p;
	const char *f;
	char x;
	struct stat s;
	char l[MAXBUFSIZE];

	if(*file != '/') {
		logger(LOG_ERR, _("`%s' is not an absolute path"), file);
		return false;
	}

	p = strrchr(file, '/');

	if(p == file)				/* It's in the root */
		p++;

	x = *p;
	*p = '\0';

	f = file;

check1:
	if(lstat(f, &s) < 0) {
		logger(LOG_ERR, _("Couldn't stat `%s': %s"), f, strerror(errno));
		return false;
	}

	if(s.st_uid != geteuid()) {
		logger(LOG_ERR, _("`%s' is owned by UID %d instead of %d"),
			   f, s.st_uid, geteuid());
		return false;
	}

	if(S_ISLNK(s.st_mode)) {
		logger(LOG_WARNING, _("Warning: `%s' is a symlink"), f);

		if(readlink(f, l, MAXBUFSIZE) < 0) {
			logger(LOG_ERR, _("Unable to read symbolic link `%s': %s"), f,
				   strerror(errno));
			return false;
		}

		f = l;
		goto check1;
	}

	*p = x;
	f = file;

check2:
	if(lstat(f, &s) < 0 && errno != ENOENT) {
		logger(LOG_ERR, _("Couldn't stat `%s': %s"), f, strerror(errno));
		return false;
	}

	if(errno == ENOENT)
		return true;

	if(s.st_uid != geteuid()) {
		logger(LOG_ERR, _("`%s' is owned by UID %d instead of %d"),
			   f, s.st_uid, geteuid());
		return false;
	}

	if(S_ISLNK(s.st_mode)) {
		logger(LOG_WARNING, _("Warning: `%s' is a symlink"), f);

		if(readlink(f, l, MAXBUFSIZE) < 0) {
			logger(LOG_ERR, _("Unable to read symbolic link `%s': %s"), f,
				   strerror(errno));
			return false;
		}

		f = l;
		goto check2;
	}

	if(s.st_mode & 0007) {
		/* Accessible by others */
		logger(LOG_ERR, _("`%s' has unsecure permissions"), f);
		return false;
	}
#endif

	return true;
}

FILE *ask_and_safe_open(const char *filename, const char *what, bool safe, const char *mode)
{
	FILE *r;
	char *directory;
	char *fn;

	/* Check stdin and stdout */
	if(!isatty(0) || !isatty(1)) {
		/* Argh, they are running us from a script or something.  Write
		   the files to the current directory and let them burn in hell
		   for ever. */
		fn = xstrdup(filename);
	} else {
		/* Ask for a file and/or directory name. */
		fprintf(stdout, _("Please enter a file to save %s to [%s]: "),
				what, filename);
		fflush(stdout);

		fn = readline(stdin, NULL, NULL);

		if(!fn) {
			fprintf(stderr, _("Error while reading stdin: %s\n"),
					strerror(errno));
			return NULL;
		}

		if(!strlen(fn))
			/* User just pressed enter. */
			fn = xstrdup(filename);
	}

	if(!strchr(fn, '/') || fn[0] != '/') {
		/* The directory is a relative path or a filename. */
		char *p;

		directory = get_current_dir_name();
		asprintf(&p, "%s/%s", directory, fn);
		free(fn);
		free(directory);
		fn = p;
	}

	umask(0077);				/* Disallow everything for group and other */

	/* Open it first to keep the inode busy */

	r = fopen(fn, mode);

	if(!r) {
		fprintf(stderr, _("Error opening file `%s': %s\n"),
				fn, strerror(errno));
		free(fn);
		return NULL;
	}

	/* Then check the file for nasty attacks */
	if(safe) {
		if(!is_safe_path(fn)) {		/* Do not permit any directories that are readable or writeable by other users. */
			fprintf(stderr, _("The file `%s' (or any of the leading directories) has unsafe permissions.\n"
					 "I will not create or overwrite this file.\n"), fn);
			fclose(r);
			free(fn);
			return NULL;
		}
	}

	free(fn);

	return r;
}
