/*
    invitation.c -- Create and accept invitations
    Copyright (C) 2013-2017 Guus Sliepen <guus@tinc-vpn.org>

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

#include "control_common.h"
#include "crypto.h"
#include "ecdsa.h"
#include "ecdsagen.h"
#include "ifconfig.h"
#include "invitation.h"
#include "names.h"
#include "netutl.h"
#include "rsagen.h"
#include "script.h"
#include "sptps.h"
#include "subnet.h"
#include "tincctl.h"
#include "utils.h"
#include "xalloc.h"

#include "ed25519/sha512.h"

int addressfamily = AF_UNSPEC;

static void scan_for_hostname(const char *filename, char **hostname, char **port) {
	if(!filename || (*hostname && *port)) {
		return;
	}

	FILE *f = fopen(filename, "r");

	if(!f) {
		return;
	}

	while(fgets(line, sizeof(line), f)) {
		if(!rstrip(line)) {
			continue;
		}

		char *p = line, *q;
		p += strcspn(p, "\t =");

		if(!*p) {
			continue;
		}

		q = p + strspn(p, "\t ");

		if(*q == '=') {
			q += 1 + strspn(q + 1, "\t ");
		}

		*p = 0;
		p = q + strcspn(q, "\t ");

		if(*p) {
			*p++ = 0;
		}

		p += strspn(p, "\t ");
		p[strcspn(p, "\t ")] = 0;

		if(!*port && !strcasecmp(line, "Port")) {
			*port = xstrdup(q);
		} else if(!*hostname && !strcasecmp(line, "Address")) {
			*hostname = xstrdup(q);

			if(*p) {
				free(*port);
				*port = xstrdup(p);
			}
		}

		if(*hostname && *port) {
			break;
		}
	}

	fclose(f);
}

char *get_my_hostname() {
	char *hostname = NULL;
	char *port = NULL;
	char *hostport = NULL;
	char *name = get_my_name(false);
	char filename[PATH_MAX] = {0};

	// Use first Address statement in own host config file
	if(check_id(name)) {
		snprintf(filename, sizeof(filename), "%s" SLASH "hosts" SLASH "%s", confbase, name);
		scan_for_hostname(filename, &hostname, &port);
		scan_for_hostname(tinc_conf, &hostname, &port);
	}

	if(hostname) {
		goto done;
	}

	// If that doesn't work, guess externally visible hostname
	fprintf(stderr, "Trying to discover externally visible hostname...\n");
	struct addrinfo *ai = str2addrinfo("tinc-vpn.org", "80", SOCK_STREAM);
	struct addrinfo *aip = ai;
	static const char request[] = "GET http://tinc-vpn.org/host.cgi HTTP/1.0\r\n\r\n";

	while(aip) {
		int s = socket(aip->ai_family, aip->ai_socktype, aip->ai_protocol);

		if(s >= 0) {
			if(connect(s, aip->ai_addr, aip->ai_addrlen)) {
				closesocket(s);
				s = -1;
			}
		}

		if(s >= 0) {
			send(s, request, sizeof(request) - 1, 0);
			int len = recv(s, line, sizeof(line) - 1, MSG_WAITALL);

			if(len > 0) {
				line[len] = 0;

				if(line[len - 1] == '\n') {
					line[--len] = 0;
				}

				char *p = strrchr(line, '\n');

				if(p && p[1]) {
					hostname = xstrdup(p + 1);
				}
			}

			closesocket(s);

			if(hostname) {
				break;
			}
		}

		aip = aip->ai_next;
		continue;
	}

	if(ai) {
		freeaddrinfo(ai);
	}

	// Check that the hostname is reasonable
	if(hostname) {
		for(char *p = hostname; *p; p++) {
			if(isalnum(*p) || *p == '-' || *p == '.' || *p == ':') {
				continue;
			}

			// If not, forget it.
			free(hostname);
			hostname = NULL;
			break;
		}
	}

	if(!tty) {
		if(!hostname) {
			fprintf(stderr, "Could not determine the external address or hostname. Please set Address manually.\n");
			free(port);
			return NULL;
		}

		goto save;
	}

again:
	fprintf(stderr, "Please enter your host's external address or hostname");

	if(hostname) {
		fprintf(stderr, " [%s]", hostname);
	}

	fprintf(stderr, ": ");

	if(!fgets(line, sizeof(line), stdin)) {
		fprintf(stderr, "Error while reading stdin: %s\n", strerror(errno));
		free(hostname);
		free(port);
		return NULL;
	}

	if(!rstrip(line)) {
		if(hostname) {
			goto save;
		} else {
			goto again;
		}
	}

	for(char *p = line; *p; p++) {
		if(isalnum(*p) || *p == '-' || *p == '.') {
			continue;
		}

		fprintf(stderr, "Invalid address or hostname.\n");
		goto again;
	}

	free(hostname);
	hostname = xstrdup(line);

save:

	if(*filename) {
		FILE *f = fopen(filename, "a");

		if(f) {
			fprintf(f, "\nAddress = %s\n", hostname);
			fclose(f);
		} else {
			fprintf(stderr, "Could not append Address to %s: %s\n", filename, strerror(errno));
		}
	}

done:

	if(port) {
		if(strchr(hostname, ':')) {
			xasprintf(&hostport, "[%s]:%s", hostname, port);
		} else {
			xasprintf(&hostport, "%s:%s", hostname, port);
		}
	} else {
		if(strchr(hostname, ':')) {
			xasprintf(&hostport, "[%s]", hostname);
		} else {
			hostport = xstrdup(hostname);
		}
	}

	free(hostname);
	free(port);
	return hostport;
}

static bool fcopy(FILE *out, const char *filename) {
	FILE *in = fopen(filename, "r");

	if(!in) {
		fprintf(stderr, "Could not open %s: %s\n", filename, strerror(errno));
		return false;
	}

	char buf[1024];
	size_t len;

	while((len = fread(buf, 1, sizeof(buf), in))) {
		fwrite(buf, len, 1, out);
	}

	fclose(in);
	return true;
}

int cmd_invite(int argc, char *argv[]) {
	if(argc < 2) {
		fprintf(stderr, "Not enough arguments!\n");
		return 1;
	}

	// Check validity of the new node's name
	if(!check_id(argv[1])) {
		fprintf(stderr, "Invalid name for node.\n");
		return 1;
	}

	myname = get_my_name(true);

	if(!myname) {
		return 1;
	}

	// Ensure no host configuration file with that name exists
	char filename[PATH_MAX];
	snprintf(filename, sizeof(filename), "%s" SLASH "hosts" SLASH "%s", confbase, argv[1]);

	if(!access(filename, F_OK)) {
		fprintf(stderr, "A host config file for %s already exists!\n", argv[1]);
		return 1;
	}

	// If a daemon is running, ensure no other nodes know about this name
	if(connect_tincd(false)) {
		bool found = false;
		sendline(fd, "%d %d", CONTROL, REQ_DUMP_NODES);

		while(recvline(fd, line, sizeof(line))) {
			char node[4096];
			int code, req;

			if(sscanf(line, "%d %d %4095s", &code, &req, node) != 3) {
				break;
			}

			if(!strcmp(node, argv[1])) {
				found = true;
			}
		}

		if(found) {
			fprintf(stderr, "A node with name %s is already known!\n", argv[1]);
			return 1;
		}
	}

	snprintf(filename, sizeof(filename), "%s" SLASH "invitations", confbase);

	if(mkdir(filename, 0700) && errno != EEXIST) {
		fprintf(stderr, "Could not create directory %s: %s\n", filename, strerror(errno));
		return 1;
	}

	// Count the number of valid invitations, clean up old ones
	DIR *dir = opendir(filename);

	if(!dir) {
		fprintf(stderr, "Could not read directory %s: %s\n", filename, strerror(errno));
		return 1;
	}

	errno = 0;
	int count = 0;
	struct dirent *ent;
	time_t deadline = time(NULL) - 604800; // 1 week in the past

	while((ent = readdir(dir))) {
		if(strlen(ent->d_name) != 24) {
			continue;
		}

		char invname[PATH_MAX];
		struct stat st;

		if((size_t)snprintf(invname, sizeof(invname), "%s" SLASH "%s", filename, ent->d_name) >= sizeof(invname)) {
			fprintf(stderr, "Filename too long: %s" SLASH "%s\n", filename, ent->d_name);
			continue;
		}

		if(!stat(invname, &st)) {
			if(deadline < st.st_mtime) {
				count++;
			} else {
				unlink(invname);
			}
		} else {
			fprintf(stderr, "Could not stat %s: %s\n", invname, strerror(errno));
			errno = 0;
		}
	}

	closedir(dir);

	if(errno) {
		fprintf(stderr, "Error while reading directory %s: %s\n", filename, strerror(errno));
		return 1;
	}

	ecdsa_t *key;
	snprintf(filename, sizeof(filename), "%s" SLASH "invitations" SLASH "ed25519_key.priv", confbase);

	// Remove the key if there are no outstanding invitations.
	if(!count) {
		unlink(filename);
	}

	// Create a new key if necessary.
	FILE *f = fopen(filename, "r");

	if(!f) {
		if(errno != ENOENT) {
			fprintf(stderr, "Could not read %s: %s\n", filename, strerror(errno));
			return 1;
		}

		key = ecdsa_generate();

		if(!key) {
			return 1;
		}

		f = fopen(filename, "w");

		if(!f) {
			fprintf(stderr, "Could not write %s: %s\n", filename, strerror(errno));
			return 1;
		}

		chmod(filename, 0600);

		if(!ecdsa_write_pem_private_key(key, f)) {
			fprintf(stderr, "Could not write ECDSA private key\n");
			fclose(f);
			return 1;
		}

		fclose(f);

		if(connect_tincd(true)) {
			sendline(fd, "%d %d", CONTROL, REQ_RELOAD);
		} else {
			fprintf(stderr, "Could not signal the tinc daemon. Please restart or reload it manually.\n");
		}
	} else {
		key = ecdsa_read_pem_private_key(f);
		fclose(f);

		if(!key) {
			fprintf(stderr, "Could not read private key from %s\n", filename);
		}
	}

	if(!key) {
		return 1;
	}

	// Create a hash of the key.
	char hash[64];
	char *fingerprint = ecdsa_get_base64_public_key(key);
	sha512(fingerprint, strlen(fingerprint), hash);
	b64encode_urlsafe(hash, hash, 18);

	// Create a random cookie for this invitation.
	char cookie[25];
	randomize(cookie, 18);

	// Create a filename that doesn't reveal the cookie itself
	char buf[18 + strlen(fingerprint)];
	char cookiehash[64];
	memcpy(buf, cookie, 18);
	memcpy(buf + 18, fingerprint, sizeof(buf) - 18);
	sha512(buf, sizeof(buf), cookiehash);
	b64encode_urlsafe(cookiehash, cookiehash, 18);

	b64encode_urlsafe(cookie, cookie, 18);

	// Create a file containing the details of the invitation.
	snprintf(filename, sizeof(filename), "%s" SLASH "invitations" SLASH "%s", confbase, cookiehash);
	int ifd = open(filename, O_RDWR | O_CREAT | O_EXCL, 0600);

	if(!ifd) {
		fprintf(stderr, "Could not create invitation file %s: %s\n", filename, strerror(errno));
		return 1;
	}

	f = fdopen(ifd, "w");

	if(!f) {
		abort();
	}

	// Get the local address
	char *address = get_my_hostname();

	// Fill in the details.
	fprintf(f, "Name = %s\n", argv[1]);

	if(check_netname(netname, true)) {
		fprintf(f, "NetName = %s\n", netname);
	}

	fprintf(f, "ConnectTo = %s\n", myname);

	// Copy Broadcast and Mode
	FILE *tc = fopen(tinc_conf, "r");

	if(tc) {
		char buf[1024];

		while(fgets(buf, sizeof(buf), tc)) {
			if((!strncasecmp(buf, "Mode", 4) && strchr(" \t=", buf[4]))
			                || (!strncasecmp(buf, "Broadcast", 9) && strchr(" \t=", buf[9]))) {
				fputs(buf, f);

				// Make sure there is a newline character.
				if(!strchr(buf, '\n')) {
					fputc('\n', f);
				}
			}
		}

		fclose(tc);
	}

	fprintf(f, "#---------------------------------------------------------------#\n");
	fprintf(f, "Name = %s\n", myname);

	char filename2[PATH_MAX];
	snprintf(filename2, sizeof(filename2), "%s" SLASH "hosts" SLASH "%s", confbase, myname);
	fcopy(f, filename2);
	fclose(f);

	// Create an URL from the local address, key hash and cookie
	char *url;
	xasprintf(&url, "%s/%s%s", address, hash, cookie);

	// Call the inviation-created script
	environment_t env;
	environment_init(&env);
	environment_add(&env, "NODE=%s", argv[1]);
	environment_add(&env, "INVITATION_FILE=%s", filename);
	environment_add(&env, "INVITATION_URL=%s", url);
	execute_script("invitation-created", &env);
	environment_exit(&env);

	puts(url);
	free(url);
	free(address);

	return 0;
}

static int sock;
static char cookie[18];
static sptps_t sptps;
static char *data;
static size_t datalen;
static bool success = false;

static char cookie[18], hash[18];

static char *get_line(const char **data) {
	if(!data || !*data) {
		return NULL;
	}

	if(! **data) {
		*data = NULL;
		return NULL;
	}

	static char line[1024];
	const char *end = strchr(*data, '\n');
	size_t len = end ? (size_t)(end - *data) : strlen(*data);

	if(len >= sizeof(line)) {
		fprintf(stderr, "Maximum line length exceeded!\n");
		return NULL;
	}

	if(len && !isprint(**data)) {
		abort();
	}

	memcpy(line, *data, len);
	line[len] = 0;

	if(end) {
		*data = end + 1;
	} else {
		*data = NULL;
	}

	return line;
}

static char *get_value(const char *data, const char *var) {
	char *line = get_line(&data);

	if(!line) {
		return NULL;
	}

	char *sep = line + strcspn(line, " \t=");
	char *val = sep + strspn(sep, " \t");

	if(*val == '=') {
		val += 1 + strspn(val + 1, " \t");
	}

	*sep = 0;

	if(strcasecmp(line, var)) {
		return NULL;
	}

	return val;
}

static char *grep(const char *data, const char *var) {
	static char value[1024];

	const char *p = data;
	int varlen = strlen(var);

	// Skip all lines not starting with var
	while(strncasecmp(p, var, varlen) || !strchr(" \t=", p[varlen])) {
		p = strchr(p, '\n');

		if(!p) {
			break;
		} else {
			p++;
		}
	}

	if(!p) {
		return NULL;
	}

	p += varlen;
	p += strspn(p, " \t");

	if(*p == '=') {
		p += 1 + strspn(p + 1, " \t");
	}

	const char *e = strchr(p, '\n');

	if(!e) {
		return xstrdup(p);
	}

	if((size_t)(e - p) >= sizeof(value)) {
		fprintf(stderr, "Maximum line length exceeded!\n");
		return NULL;
	}

	memcpy(value, p, e - p);
	value[e - p] = 0;
	return value;
}

static bool finalize_join(void) {
	const char *temp_name = get_value(data, "Name");

	if(!temp_name) {
		fprintf(stderr, "No Name found in invitation!\n");
		return false;
	}

	size_t len = strlen(temp_name);
	char name[len + 1];
	memcpy(name, temp_name, len);
	name[len] = 0;

	if(!check_id(name)) {
		fprintf(stderr, "Invalid Name found in invitation!\n");
		return false;
	}

	if(!netname) {
		netname = grep(data, "NetName");

		if(netname && !check_netname(netname, true)) {
			fprintf(stderr, "Unsafe NetName found in invitation!\n");
			return false;
		}
	}

	bool ask_netname = false;
	char temp_netname[32];

make_names:

	if(!confbasegiven) {
		free(confbase);
		confbase = NULL;
	}

	make_names(false);

	free(tinc_conf);
	free(hosts_dir);

	xasprintf(&tinc_conf, "%s" SLASH "tinc.conf", confbase);
	xasprintf(&hosts_dir, "%s" SLASH "hosts", confbase);

	if(!access(tinc_conf, F_OK)) {
		fprintf(stderr, "Configuration file %s already exists!\n", tinc_conf);

		if(confbasegiven) {
			return false;
		}

		// Generate a random netname, ask for a better one later.
		ask_netname = true;
		snprintf(temp_netname, sizeof(temp_netname), "join_%x", rand());
		netname = temp_netname;
		goto make_names;
	}

	if(mkdir(confbase, 0777) && errno != EEXIST) {
		fprintf(stderr, "Could not create directory %s: %s\n", confbase, strerror(errno));
		return false;
	}

	if(mkdir(hosts_dir, 0777) && errno != EEXIST) {
		fprintf(stderr, "Could not create directory %s: %s\n", hosts_dir, strerror(errno));
		return false;
	}

	FILE *f = fopen(tinc_conf, "w");

	if(!f) {
		fprintf(stderr, "Could not create file %s: %s\n", tinc_conf, strerror(errno));
		return false;
	}

	fprintf(f, "Name = %s\n", name);

	char filename[PATH_MAX];
	snprintf(filename, sizeof(filename), "%s" SLASH "%s", hosts_dir, name);
	FILE *fh = fopen(filename, "w");

	if(!fh) {
		fprintf(stderr, "Could not create file %s: %s\n", filename, strerror(errno));
		fclose(f);
		return false;
	}

	snprintf(filename, sizeof(filename), "%s" SLASH "invitation-data", confbase);
	FILE *finv = fopen(filename, "w");

	if(!finv || fwrite(data, datalen, 1, finv) != 1) {
		fprintf(stderr, "Could not create file %s: %s\n", filename, strerror(errno));
		fclose(fh);
		fclose(f);
		fclose(finv);
		return false;
	}

	fclose(finv);

	snprintf(filename, sizeof(filename), "%s" SLASH "tinc-up.invitation", confbase);
	FILE *fup = fopen(filename, "w");

	if(!fup) {
		fprintf(stderr, "Could not create file %s: %s\n", filename, strerror(errno));
		fclose(f);
		fclose(fh);
		return false;
	}

	ifconfig_header(fup);

	// Filter first chunk on approved keywords, split between tinc.conf and hosts/Name
	// Generate a tinc-up script from Ifconfig and Route keywords.
	// Other chunks go unfiltered to their respective host config files
	const char *p = data;
	char *l, *value;

	while((l = get_line(&p))) {
		// Ignore comments
		if(*l == '#') {
			continue;
		}

		// Split line into variable and value
		int len = strcspn(l, "\t =");
		value = l + len;
		value += strspn(value, "\t ");

		if(*value == '=') {
			value++;
			value += strspn(value, "\t ");
		}

		l[len] = 0;

		// Ignore lines with empty variable names
		if(!*l) {
			continue;
		}

		// Is it a Name?
		if(!strcasecmp(l, "Name")) {
			if(strcmp(value, name)) {
				break;
			} else {
				continue;
			}
		} else if(!strcasecmp(l, "NetName")) {
			continue;
		}

		// Check the list of known variables
		bool found = false;
		int i;

		for(i = 0; variables[i].name; i++) {
			if(strcasecmp(l, variables[i].name)) {
				continue;
			}

			found = true;
			break;
		}

		// Handle Ifconfig and Route statements
		if(!found) {
			if(!strcasecmp(l, "Ifconfig")) {
				if(!strcasecmp(value, "dhcp")) {
					ifconfig_dhcp(fup);
				} else if(!strcasecmp(value, "dhcp6")) {
					ifconfig_dhcp6(fup);
				} else if(!strcasecmp(value, "slaac")) {
					ifconfig_slaac(fup);
				} else {
					ifconfig_address(fup, value);
				}

				continue;
			} else if(!strcasecmp(l, "Route")) {
				ifconfig_route(fup, value);
				continue;
			}
		}

		// Ignore unknown and unsafe variables
		if(!found) {
			fprintf(stderr, "Ignoring unknown variable '%s' in invitation.\n", l);
			continue;
		} else if(!(variables[i].type & VAR_SAFE)) {
			fprintf(stderr, "Ignoring unsafe variable '%s' in invitation.\n", l);
			continue;
		}

		// Copy the safe variable to the right config file
		fprintf((variables[i].type & VAR_HOST) ? fh : f, "%s = %s\n", l, value);
	}

	fclose(f);
	bool valid_tinc_up = ifconfig_footer(fup);
	fclose(fup);

	while(l && !strcasecmp(l, "Name")) {
		if(!check_id(value)) {
			fprintf(stderr, "Invalid Name found in invitation.\n");
			return false;
		}

		if(!strcmp(value, name)) {
			fprintf(stderr, "Secondary chunk would overwrite our own host config file.\n");
			return false;
		}

		snprintf(filename, sizeof(filename), "%s" SLASH "%s", hosts_dir, value);
		f = fopen(filename, "w");

		if(!f) {
			fprintf(stderr, "Could not create file %s: %s\n", filename, strerror(errno));
			return false;
		}

		while((l = get_line(&p))) {
			if(!strcmp(l, "#---------------------------------------------------------------#")) {
				continue;
			}

			int len = strcspn(l, "\t =");

			if(len == 4 && !strncasecmp(l, "Name", 4)) {
				value = l + len;
				value += strspn(value, "\t ");

				if(*value == '=') {
					value++;
					value += strspn(value, "\t ");
				}

				l[len] = 0;
				break;
			}

			fputs(l, f);
			fputc('\n', f);
		}

		fclose(f);
	}

	// Generate our key and send a copy to the server
	ecdsa_t *key = ecdsa_generate();

	if(!key) {
		return false;
	}

	char *b64key = ecdsa_get_base64_public_key(key);

	if(!b64key) {
		return false;
	}

	snprintf(filename, sizeof(filename), "%s" SLASH "ed25519_key.priv", confbase);
	f = fopenmask(filename, "w", 0600);

	if(!f) {
		return false;
	}

	if(!ecdsa_write_pem_private_key(key, f)) {
		fprintf(stderr, "Error writing private key!\n");
		ecdsa_free(key);
		fclose(f);
		return false;
	}

	fclose(f);

	fprintf(fh, "Ed25519PublicKey = %s\n", b64key);

	sptps_send_record(&sptps, 1, b64key, strlen(b64key));
	free(b64key);
	ecdsa_free(key);

#ifndef DISABLE_LEGACY
	rsa_t *rsa = rsa_generate(2048, 0x1001);
	snprintf(filename, sizeof(filename), "%s" SLASH "rsa_key.priv", confbase);
	f = fopenmask(filename, "w", 0600);

	if(!f || !rsa_write_pem_private_key(rsa, f)) {
		fprintf(stderr, "Could not write private RSA key\n");
	} else if(!rsa_write_pem_public_key(rsa, fh)) {
		fprintf(stderr, "Could not write public RSA key\n");
	}

	fclose(f);

	fclose(fh);

	rsa_free(rsa);
#endif

	check_port(name);

ask_netname:

	if(ask_netname && tty) {
		fprintf(stderr, "Enter a new netname: ");

		if(!fgets(line, sizeof(line), stdin)) {
			fprintf(stderr, "Error while reading stdin: %s\n", strerror(errno));
			return false;
		}

		if(!*line || *line == '\n') {
			goto ask_netname;
		}

		line[strlen(line) - 1] = 0;

		char newbase[PATH_MAX];

		if((size_t)snprintf(newbase, sizeof(newbase), CONFDIR SLASH "tinc" SLASH "%s", line) >= sizeof(newbase)) {
			fprintf(stderr, "Filename too long: " CONFDIR SLASH "tinc" SLASH "%s\n", line);
			goto ask_netname;
		}

		if(rename(confbase, newbase)) {
			fprintf(stderr, "Error trying to rename %s to %s: %s\n", confbase, newbase, strerror(errno));
			goto ask_netname;
		}

		netname = line;
		make_names(false);
	}

	char filename2[PATH_MAX];
	snprintf(filename, sizeof(filename), "%s" SLASH "tinc-up.invitation", confbase);
	snprintf(filename2, sizeof(filename2), "%s" SLASH "tinc-up", confbase);

	if(valid_tinc_up) {
		if(tty) {
			FILE *fup = fopen(filename, "r");

			if(fup) {
				fprintf(stderr, "\nPlease review the following tinc-up script:\n\n");

				char buf[MAXSIZE];

				while(fgets(buf, sizeof(buf), fup)) {
					fputs(buf, stderr);
				}

				fclose(fup);

				int response = 0;

				do {
					fprintf(stderr, "\nDo you want to use this script [y]es/[n]o/[e]dit? ");
					response = tolower(getchar());
				} while(!strchr("yne", response));

				fprintf(stderr, "\n");

				if(response == 'e') {
					char *command;
#ifndef HAVE_MINGW
					const char *editor = getenv("VISUAL");
					if (!editor)
						editor = getenv("EDITOR");
					if (!editor)
						editor = "vi";

					xasprintf(&command, "\"%s\" \"%s\"", editor, filename);
#else
					xasprintf(&command, "edit \"%s\"", filename);
#endif

					if(system(command)) {
						response = 'n';
					} else {
						response = 'y';
					}

					free(command);
				}

				if(response == 'y') {
					rename(filename, filename2);
					chmod(filename2, 0755);
					fprintf(stderr, "tinc-up enabled.\n");
				} else {
					fprintf(stderr, "tinc-up has been left disabled.\n");
				}
			}
		} else {
			fprintf(stderr, "A tinc-up script was generated, but has been left disabled.\n");
		}
	} else {
		// A placeholder was generated.
		rename(filename, filename2);
		chmod(filename2, 0755);
	}

	fprintf(stderr, "Configuration stored in: %s\n", confbase);

	return true;
}


static bool invitation_send(void *handle, uint8_t type, const void *vdata, size_t len) {
	(void)handle;
	(void)type;
	const char *data = vdata;

	while(len) {
		int result = send(sock, data, len, 0);

		if(result == -1 && errno == EINTR) {
			continue;
		} else if(result <= 0) {
			return false;
		}

		data += result;
		len -= result;
	}

	return true;
}

static bool invitation_receive(void *handle, uint8_t type, const void *msg, uint16_t len) {
	(void)handle;

	switch(type) {
	case SPTPS_HANDSHAKE:
		return sptps_send_record(&sptps, 0, cookie, sizeof(cookie));

	case 0:
		data = xrealloc(data, datalen + len + 1);
		memcpy(data + datalen, msg, len);
		datalen += len;
		data[datalen] = 0;
		break;

	case 1:
		return finalize_join();

	case 2:
		fprintf(stderr, "Invitation successfully accepted.\n");
		shutdown(sock, SHUT_RDWR);
		success = true;
		break;

	default:
		return false;
	}

	return true;
}

int cmd_join(int argc, char *argv[]) {
	free(data);
	data = NULL;
	datalen = 0;

	if(argc > 2) {
		fprintf(stderr, "Too many arguments!\n");
		return 1;
	}

	// Make sure confbase exists and is accessible.
	if(!confbase_given && mkdir(confdir, 0755) && errno != EEXIST) {
		fprintf(stderr, "Could not create directory %s: %s\n", confdir, strerror(errno));
		return 1;
	}

	if(mkdir(confbase, 0777) && errno != EEXIST) {
		fprintf(stderr, "Could not create directory %s: %s\n", confbase, strerror(errno));
		return 1;
	}

	if(access(confbase, R_OK | W_OK | X_OK)) {
		fprintf(stderr, "No permission to write in directory %s: %s\n", confbase, strerror(errno));
		return 1;
	}

	// If a netname or explicit configuration directory is specified, check for an existing tinc.conf.
	if((netname || confbasegiven) && !access(tinc_conf, F_OK)) {
		fprintf(stderr, "Configuration file %s already exists!\n", tinc_conf);
		return 1;
	}

	// Either read the invitation from the command line or from stdin.
	char *invitation;

	if(argc > 1) {
		invitation = argv[1];
	} else {
		if(tty) {
			fprintf(stderr, "Enter invitation URL: ");
		}

		errno = EPIPE;

		if(!fgets(line, sizeof(line), stdin)) {
			fprintf(stderr, "Error while reading stdin: %s\n", strerror(errno));
			return false;
		}

		invitation = line;
	}

	// Parse the invitation URL.
	rstrip(line);

	char *slash = strchr(invitation, '/');

	if(!slash) {
		goto invalid;
	}

	*slash++ = 0;

	if(strlen(slash) != 48) {
		goto invalid;
	}

	char *address = invitation;
	char *port = NULL;

	if(*address == '[') {
		address++;
		char *bracket = strchr(address, ']');

		if(!bracket) {
			goto invalid;
		}

		*bracket = 0;

		if(bracket[1] == ':') {
			port = bracket + 2;
		}
	} else {
		port = strchr(address, ':');

		if(port) {
			*port++ = 0;
		}
	}

	if(!port || !*port) {
		port = "655";
	}

	if(!b64decode(slash, hash, 24) || !b64decode(slash + 24, cookie, 24)) {
		goto invalid;
	}

	// Generate a throw-away key for the invitation.
	ecdsa_t *key = ecdsa_generate();

	if(!key) {
		return 1;
	}

	char *b64key = ecdsa_get_base64_public_key(key);

	// Connect to the tinc daemon mentioned in the URL.
	struct addrinfo *ai = str2addrinfo(address, port, SOCK_STREAM);

	if(!ai) {
		return 1;
	}

	struct addrinfo *aip = NULL;

next:
	if(!aip) {
		aip = ai;
	} else {
		aip = aip->ai_next;

		if(!aip) {
			freeaddrinfo(ai);
			return 1;
		}
	}

	sock = socket(aip->ai_family, aip->ai_socktype, aip->ai_protocol);

	if(sock <= 0) {
		fprintf(stderr, "Could not open socket: %s\n", strerror(errno));
		goto next;
	}

	if(connect(sock, aip->ai_addr, aip->ai_addrlen)) {
		char *addrstr, *portstr;
		sockaddr2str((sockaddr_t *)aip->ai_addr, &addrstr, &portstr);
		fprintf(stderr, "Could not connect to %s port %s: %s\n", addrstr, portstr, strerror(errno));
		free(addrstr);
		free(portstr);
		closesocket(sock);
		goto next;
	}

	fprintf(stderr, "Connected to %s port %s...\n", address, port);

	// Tell him we have an invitation, and give him our throw-away key.
	int len = snprintf(line, sizeof(line), "0 ?%s %d.%d\n", b64key, PROT_MAJOR, PROT_MINOR);

	if(len <= 0 || (size_t)len >= sizeof(line)) {
		abort();
	}

	if(!sendline(sock, "0 ?%s %d.%d", b64key, PROT_MAJOR, 1)) {
		fprintf(stderr, "Error sending request to %s port %s: %s\n", address, port, strerror(errno));
		closesocket(sock);
		goto next;
	}

	char hisname[4096] = "";
	int code, hismajor, hisminor = 0;

	if(!recvline(sock, line, sizeof(line)) || sscanf(line, "%d %4095s %d.%d", &code, hisname, &hismajor, &hisminor) < 3 || code != 0 || hismajor != PROT_MAJOR || !check_id(hisname) || !recvline(sock, line, sizeof(line)) || !rstrip(line) || sscanf(line, "%d ", &code) != 1 || code != ACK || strlen(line) < 3) {
		fprintf(stderr, "Cannot read greeting from peer\n");
		closesocket(sock);
		goto next;
	}

	freeaddrinfo(ai);

	// Check if the hash of the key he gave us matches the hash in the URL.
	char *fingerprint = line + 2;
	char hishash[64];

	if(sha512(fingerprint, strlen(fingerprint), hishash)) {
		fprintf(stderr, "Could not create digest\n%s\n", line + 2);
		return 1;
	}

	if(memcmp(hishash, hash, 18)) {
		fprintf(stderr, "Peer has an invalid key!\n%s\n", line + 2);
		return 1;

	}

	ecdsa_t *hiskey = ecdsa_set_base64_public_key(fingerprint);

	if(!hiskey) {
		return 1;
	}

	// Start an SPTPS session
	if(!sptps_start(&sptps, NULL, true, false, key, hiskey, "tinc invitation", 15, invitation_send, invitation_receive)) {
		return 1;
	}

	// Feed rest of input buffer to SPTPS
	if(!sptps_receive_data(&sptps, buffer, blen)) {
		return 1;
	}

	while((len = recv(sock, line, sizeof(line), 0))) {
		if(len < 0) {
			if(errno == EINTR) {
				continue;
			}

			fprintf(stderr, "Error reading data from %s port %s: %s\n", address, port, strerror(errno));
			return 1;
		}

		char *p = line;

		while(len) {
			int done = sptps_receive_data(&sptps, p, len);

			if(!done) {
				return 1;
			}

			len -= done;
			p += done;
		}
	}

	sptps_stop(&sptps);
	ecdsa_free(hiskey);
	ecdsa_free(key);
	closesocket(sock);

	if(!success) {
		fprintf(stderr, "Connection closed by peer, invitation cancelled.\n");
		return 1;
	}

	return 0;

invalid:
	fprintf(stderr, "Invalid invitation URL.\n");
	return 1;
}
