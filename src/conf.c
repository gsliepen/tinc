/*
    conf.c -- configuration code
    Copyright (C) 1998      Robert van der Meulen
                  1998-2005 Ivo Timmermans
                  2000      Cris van Pelt
                  2010-2011 Julien Muchembled <jm@jmuchemb.eu>
                  2000-2013 Guus Sliepen <guus@tinc-vpn.org>
                  2013      Florent Clairambault <florent@clairambault.fr>

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/

#include "system.h"

#include "splay_tree.h"
#include "connection.h"
#include "conf.h"
#include "list.h"
#include "logger.h"
#include "names.h"
#include "netutl.h"             /* for str2address */
#include "protocol.h"
#include "utils.h"              /* for cp */
#include "xalloc.h"

splay_tree_t *config_tree;

int pinginterval = 0;           /* seconds between pings */
int pingtimeout = 0;            /* seconds to wait for response */
list_t *cmdline_conf = NULL;    /* global/host configuration values given at the command line */

static int config_compare(const config_t *a, const config_t *b) {
	int result;

	result = strcasecmp(a->variable, b->variable);

	if(result)
		return result;

	/* give priority to command line options */
	result = !b->file - !a->file;
	if (result)
		return result;

	result = a->line - b->line;

	if(result)
		return result;
	else
		return a->file ? strcmp(a->file, b->file) : 0;
}

void init_configuration(splay_tree_t ** config_tree) {
	*config_tree = splay_alloc_tree((splay_compare_t) config_compare, (splay_action_t) free_config);
}

void exit_configuration(splay_tree_t ** config_tree) {
	splay_delete_tree(*config_tree);
	*config_tree = NULL;
}

config_t *new_config(void) {
	return xzalloc(sizeof(config_t));
}

void free_config(config_t *cfg) {
	if(cfg->variable)
		free(cfg->variable);

	if(cfg->value)
		free(cfg->value);

	if(cfg->file)
		free(cfg->file);

	free(cfg);
}

void config_add(splay_tree_t *config_tree, config_t *cfg) {
	splay_insert(config_tree, cfg);
}

config_t *lookup_config(splay_tree_t *config_tree, char *variable) {
	config_t cfg, *found;

	cfg.variable = variable;
	cfg.file = NULL;
	cfg.line = 0;

	found = splay_search_closest_greater(config_tree, &cfg);

	if(!found)
		return NULL;

	if(strcasecmp(found->variable, variable))
		return NULL;

	return found;
}

config_t *lookup_config_next(splay_tree_t *config_tree, const config_t *cfg) {
	splay_node_t *node;
	config_t *found;

	node = splay_search_node(config_tree, cfg);

	if(node) {
		if(node->next) {
			found = node->next->data;

			if(!strcasecmp(found->variable, cfg->variable))
				return found;
		}
	}

	return NULL;
}

bool get_config_bool(const config_t *cfg, bool *result) {
	if(!cfg)
		return false;

	if(!strcasecmp(cfg->value, "yes")) {
		*result = true;
		return true;
	} else if(!strcasecmp(cfg->value, "no")) {
		*result = false;
		return true;
	}

	logger(DEBUG_ALWAYS, LOG_ERR, "\"yes\" or \"no\" expected for configuration variable %s in %s line %d",
		   cfg->variable, cfg->file, cfg->line);

	return false;
}

bool get_config_int(const config_t *cfg, int *result) {
	if(!cfg)
		return false;

	if(sscanf(cfg->value, "%d", result) == 1)
		return true;

	logger(DEBUG_ALWAYS, LOG_ERR, "Integer expected for configuration variable %s in %s line %d",
		   cfg->variable, cfg->file, cfg->line);

	return false;
}

bool get_config_string(const config_t *cfg, char **result) {
	if(!cfg)
		return false;

	*result = xstrdup(cfg->value);

	return true;
}

bool get_config_address(const config_t *cfg, struct addrinfo **result) {
	struct addrinfo *ai;

	if(!cfg)
		return false;

	ai = str2addrinfo(cfg->value, NULL, 0);

	if(ai) {
		*result = ai;
		return true;
	}

	logger(DEBUG_ALWAYS, LOG_ERR, "Hostname or IP address expected for configuration variable %s in %s line %d",
		   cfg->variable, cfg->file, cfg->line);

	return false;
}

bool get_config_subnet(const config_t *cfg, subnet_t ** result) {
	subnet_t subnet = {NULL};

	if(!cfg)
		return false;

	if(!str2net(&subnet, cfg->value)) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Subnet expected for configuration variable %s in %s line %d",
			   cfg->variable, cfg->file, cfg->line);
		return false;
	}

	/* Teach newbies what subnets are... */

	if(((subnet.type == SUBNET_IPV4)
		&& !maskcheck(&subnet.net.ipv4.address, subnet.net.ipv4.prefixlength, sizeof subnet.net.ipv4.address))
		|| ((subnet.type == SUBNET_IPV6)
		&& !maskcheck(&subnet.net.ipv6.address, subnet.net.ipv6.prefixlength, sizeof subnet.net.ipv6.address))) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Network address and prefix length do not match for configuration variable %s in %s line %d",
			   cfg->variable, cfg->file, cfg->line);
		return false;
	}

	*(*result = new_subnet()) = subnet;

	return true;
}

/*
  Read exactly one line and strip the trailing newline if any.
*/
static char *readline(FILE * fp, char *buf, size_t buflen) {
	char *newline = NULL;
	char *p;

	if(feof(fp))
		return NULL;

	p = fgets(buf, buflen, fp);

	if(!p)
		return NULL;

	newline = strchr(p, '\n');

	if(!newline)
		return buf;

	/* kill newline and carriage return if necessary */
	*newline = '\0';
	if(newline > p && newline[-1] == '\r')
		newline[-1] = '\0';

	return buf;
}

config_t *parse_config_line(char *line, const char *fname, int lineno) {
	config_t *cfg;
	int len;
	char *variable, *value, *eol;
	variable = value = line;

	eol = line + strlen(line);
	while(strchr("\t ", *--eol))
		*eol = '\0';

	len = strcspn(value, "\t =");
	value += len;
	value += strspn(value, "\t ");
	if(*value == '=') {
		value++;
		value += strspn(value, "\t ");
	}
	variable[len] = '\0';

	if(!*value) {
		const char err[] = "No value for variable";
		if (fname)
			logger(DEBUG_ALWAYS, LOG_ERR, "%s `%s' on line %d while reading config file %s",
				err, variable, lineno, fname);
		else
			logger(DEBUG_ALWAYS, LOG_ERR, "%s `%s' in command line option %d",
				err, variable, lineno);
		return NULL;
	}

	cfg = new_config();
	cfg->variable = xstrdup(variable);
	cfg->value = xstrdup(value);
	cfg->file = fname ? xstrdup(fname) : NULL;
	cfg->line = lineno;

	return cfg;
}

/*
  Parse a configuration file and put the results in the configuration tree
  starting at *base.
*/
bool read_config_file(splay_tree_t *config_tree, const char *fname) {
	FILE *fp;
	char buffer[MAX_STRING_SIZE];
	char *line;
	int lineno = 0;
	bool ignore = false;
	config_t *cfg;
	bool result = false;

	fp = fopen(fname, "r");

	if(!fp) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Cannot open config file %s: %s", fname, strerror(errno));
		return false;
	}

	for(;;) {
		line = readline(fp, buffer, sizeof buffer);

		if(!line) {
			if(feof(fp))
				result = true;
			break;
		}

		lineno++;

		if(!*line || *line == '#')
			continue;

		if(ignore) {
			if(!strncmp(line, "-----END", 8))
				ignore = false;
			continue;
		}

		if(!strncmp(line, "-----BEGIN", 10)) {
			ignore = true;
			continue;
		}

		cfg = parse_config_line(line, fname, lineno);
		if (!cfg)
			break;
		config_add(config_tree, cfg);
	}

	fclose(fp);

	return result;
}

void read_config_options(splay_tree_t *config_tree, const char *prefix) {
	size_t prefix_len = prefix ? strlen(prefix) : 0;

	for(const list_node_t *node = cmdline_conf->tail; node; node = node->prev) {
		const config_t *cfg = node->data;
		config_t *new;

		if(!prefix) {
			if(strchr(cfg->variable, '.'))
				continue;
		} else {
			if(strncmp(prefix, cfg->variable, prefix_len) ||
			   cfg->variable[prefix_len] != '.')
				continue;
		}

		new = new_config();
		if(prefix)
			new->variable = xstrdup(cfg->variable + prefix_len + 1);
		else
			new->variable = xstrdup(cfg->variable);
		new->value = xstrdup(cfg->value);
		new->file = NULL;
		new->line = cfg->line;

		config_add(config_tree, new);
	}
}

bool read_server_config(void) {
	char *fname;
	bool x;

	read_config_options(config_tree, NULL);

	xasprintf(&fname, "%s" SLASH "tinc.conf", confbase);
	errno = 0;
	x = read_config_file(config_tree, fname);

	// We will try to read the conf files in the "conf.d" dir
	if (x) {
		char * dname;
		xasprintf(&dname, "%s" SLASH "conf.d", confbase);
		DIR *dir = opendir (dname);
		// If we can find this dir
		if (dir) { 
			struct dirent *ep;
			// We list all the files in it
			while (x && (ep = readdir (dir))) {
				size_t l = strlen(ep->d_name);
				// And we try to read the ones that end with ".conf"
				if (l > 5 && !strcmp(".conf", & ep->d_name[ l - 5 ])) {
					free(fname);
					xasprintf(&fname, "%s" SLASH "%s", dname, ep->d_name);
					x = read_config_file(config_tree, fname);
				}
			}
			closedir (dir);
		}
		free(dname);
	}

	if(!x && errno)
		logger(DEBUG_ALWAYS, LOG_ERR, "Failed to read `%s': %s", fname, strerror(errno));

	free(fname);

	return x;
}

bool read_host_config(splay_tree_t *config_tree, const char *name) {
	char *fname;
	bool x;

	read_config_options(config_tree, name);

	xasprintf(&fname, "%s" SLASH "hosts" SLASH "%s", confbase, name);
	x = read_config_file(config_tree, fname);
	free(fname);

	return x;
}

bool append_config_file(const char *name, const char *key, const char *value) {
	char *fname;
	xasprintf(&fname, "%s" SLASH "hosts" SLASH "%s", confbase, name);

	FILE *fp = fopen(fname, "a");

	if(!fp) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Cannot open config file %s: %s", fname, strerror(errno));
	} else {
		fprintf(fp, "\n# The following line was automatically added by tinc\n%s = %s\n", key, value);
		fclose(fp);
	}

	free(fname);

	return fp != NULL;
}
