/*
    fsck.c -- Check the configuration files for problems
    Copyright (C) 2014 Guus Sliepen <guus@tinc-vpn.org>

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

#include "crypto.h"
#include "ecdsa.h"
#include "ecdsagen.h"
#include "fsck.h"
#include "names.h"
#ifndef DISABLE_LEGACY
#include "rsa.h"
#include "rsagen.h"
#endif
#include "tincctl.h"
#include "utils.h"

static bool ask_fix(void) {
	if(force)
		return true;
	if(!tty)
		return false;
again:
	fprintf(stderr, "Fix y/n? ");
	char buf[1024];
	if(!fgets(buf, sizeof buf, stdin)) {
		tty = false;
		return false;
	}
	if(buf[0] == 'y' || buf[0] == 'Y')
		return true;
	if(buf[0] == 'n' || buf[0] == 'N')
		return false;
	goto again;
}

static void print_tinc_cmd(const char *argv0, const char *format, ...) {
	if(confbasegiven)
		fprintf(stderr, "%s -c %s ", argv0, confbase);
	else if(netname)
		fprintf(stderr, "%s -n %s ", argv0, netname);
	else
		fprintf(stderr, "%s ", argv0);
	va_list va;
	va_start(va, format);
	vfprintf(stderr, format, va);
	va_end(va);
	fputc('\n', stderr);
}

static int strtailcmp(const char *str, const char *tail) {
	size_t slen = strlen(str);
	size_t tlen = strlen(tail);
	if(tlen > slen)
		return -1;
	return memcmp(str + slen - tlen, tail, tlen);
}

static void check_conffile(const char *fname, bool server) {
	FILE *f = fopen(fname, "r");
	if(!f) {
		fprintf(stderr, "ERROR: cannot read %s: %s\n", fname, strerror(errno));
		return;
	}

	char line[2048];
	int lineno = 0;
	bool skip = false;
	const int maxvariables = 50;
	int count[maxvariables];
	memset(count, 0, sizeof count);

	while(fgets(line, sizeof line, f)) {
		if(skip) {
			if(!strncmp(line, "-----END", 8))
				skip = false;
			continue;
		} else {
			if(!strncmp(line, "-----BEGIN", 10)) {
				skip = true;
				continue;
			}
		}

		int len;
		char *variable, *value, *eol;
		variable = value = line;

		lineno++;

		eol = line + strlen(line);
		while(strchr("\t \r\n", *--eol))
			*eol = '\0';

		if(!line[0] || line[0] == '#')
			continue;

		len = strcspn(value, "\t =");
		value += len;
		value += strspn(value, "\t ");
		if(*value == '=') {
			value++;
			value += strspn(value, "\t ");
		}
		variable[len] = '\0';

		bool found = false;

		for(int i = 0; variables[i].name; i++) {
			if(strcasecmp(variables[i].name, variable))
				continue;

			found = true;

			if(variables[i].type & VAR_OBSOLETE) {
				fprintf(stderr, "WARNING: obsolete variable %s in %s line %d\n", variable, fname, lineno);
			}

			if(i < maxvariables)
				count[i]++;
		}

		if(!found)
			fprintf(stderr, "WARNING: unknown variable %s in %s line %d\n", variable, fname, lineno);

		if(!*value)
			fprintf(stderr, "ERROR: no value for variable %s in %s line %d\n", variable, fname, lineno);
	}

	for(int i = 0; variables[i].name && i < maxvariables; i++) {
		if(count[i] > 1 && !(variables[i].type & VAR_MULTIPLE))
			fprintf(stderr, "WARNING: multiple instances of variable %s in %s\n", variables[i].name, fname);
	}

	if(ferror(f))
		fprintf(stderr, "ERROR: while reading %s: %s\n", fname, strerror(errno));

	fclose(f);
}

int fsck(const char *argv0) {
#ifdef HAVE_MINGW
	int uid = 0;
#else
	uid_t uid = getuid();
#endif

	// Check that tinc.conf is readable.

	if(access(tinc_conf, R_OK)) {
		fprintf(stderr, "ERROR: cannot read %s: %s\n", tinc_conf, strerror(errno));
		if(errno == ENOENT) {
			fprintf(stderr, "No tinc configuration found. Create a new one with:\n\n");
			print_tinc_cmd(argv0, "init");
		} else if(errno == EACCES) {
			if(uid != 0)
				fprintf(stderr, "You are currently not running tinc as root. Use sudo?\n");
			else
				fprintf(stderr, "Check the permissions of each component of the path %s.\n", tinc_conf);
		}
		return 1;
	}

	char *name = get_my_name(true);
	if(!name) {
		fprintf(stderr, "ERROR: tinc cannot run without a valid Name.\n");
		return 1;
	}

	// Check for private keys.
	// TODO: use RSAPrivateKeyFile and Ed25519PrivateKeyFile variables if present.

	struct stat st;
	char fname[PATH_MAX];
	char dname[PATH_MAX];

#ifndef DISABLE_LEGACY
	rsa_t *rsa_priv = NULL;
	snprintf(fname, sizeof fname, "%s/rsa_key.priv", confbase);

	if(stat(fname, &st)) {
		if(errno != ENOENT) {
			// Something is seriously wrong here. If we can access the directory with tinc.conf in it, we should certainly be able to stat() an existing file.
			fprintf(stderr, "ERROR: cannot read %s: %s\n", fname, strerror(errno));
			fprintf(stderr, "Please correct this error.\n");
			return 1;
		}
	} else {
		FILE *f = fopen(fname, "r");
		if(!f) {
			fprintf(stderr, "ERROR: could not open %s: %s\n", fname, strerror(errno));
			return 1;
		}
		rsa_priv = rsa_read_pem_private_key(f);
		fclose(f);
		if(!rsa_priv) {
			fprintf(stderr, "ERROR: No key or unusable key found in %s.\n", fname);
			fprintf(stderr, "You can generate a new RSA key with:\n\n");
			print_tinc_cmd(argv0, "generate-rsa-keys");
			return 1;
		}

#if !defined(HAVE_MINGW) && !defined(HAVE_CYGWIN)
		if(st.st_mode & 077) {
			fprintf(stderr, "WARNING: unsafe file permissions on %s.\n", fname);
			if(st.st_uid != uid) {
				fprintf(stderr, "You are not running %s as the same uid as %s.\n", argv0, fname);
			} else if(ask_fix()) {
				if(chmod(fname, st.st_mode & ~077))
					fprintf(stderr, "ERROR: could not change permissions of %s: %s\n", fname, strerror(errno));
				else
					fprintf(stderr, "Fixed permissions of %s.\n", fname);
			}
		}
#endif
	}
#endif

	ecdsa_t *ecdsa_priv = NULL;
	snprintf(fname, sizeof fname, "%s/ed25519_key.priv", confbase);

	if(stat(fname, &st)) {
		if(errno != ENOENT) {
			// Something is seriously wrong here. If we can access the directory with tinc.conf in it, we should certainly be able to stat() an existing file.
			fprintf(stderr, "ERROR: cannot read %s: %s\n", fname, strerror(errno));
			fprintf(stderr, "Please correct this error.\n");
			return 1;
		}
	} else {
		FILE *f = fopen(fname, "r");
		if(!f) {
			fprintf(stderr, "ERROR: could not open %s: %s\n", fname, strerror(errno));
			return 1;
		}
		ecdsa_priv = ecdsa_read_pem_private_key(f);
		fclose(f);
		if(!ecdsa_priv) {
			fprintf(stderr, "ERROR: No key or unusable key found in %s.\n", fname);
			fprintf(stderr, "You can generate a new Ed25519 key with:\n\n");
			print_tinc_cmd(argv0, "generate-ed25519-keys");
			return 1;
		}

#if !defined(HAVE_MINGW) && !defined(HAVE_CYGWIN)
		if(st.st_mode & 077) {
			fprintf(stderr, "WARNING: unsafe file permissions on %s.\n", fname);
			if(st.st_uid != uid) {
				fprintf(stderr, "You are not running %s as the same uid as %s.\n", argv0, fname);
			} else if(ask_fix()) {
				if(chmod(fname, st.st_mode & ~077))
					fprintf(stderr, "ERROR: could not change permissions of %s: %s\n", fname, strerror(errno));
				else
					fprintf(stderr, "Fixed permissions of %s.\n", fname);
			}
		}
#endif
	}

#ifdef DISABLE_LEGACY
	if(!ecdsa_priv) {
		fprintf(stderr, "ERROR: No Ed25519 private key found.\n");
#else
	if(!rsa_priv && !ecdsa_priv) {
		fprintf(stderr, "ERROR: Neither RSA or Ed25519 private key found.\n");
#endif
		fprintf(stderr, "You can generate new keys with:\n\n");
		print_tinc_cmd(argv0, "generate-keys");
		return 1;
	}

	// Check for public keys.
	// TODO: use RSAPublicKeyFile variable if present.

	snprintf(fname, sizeof fname, "%s/hosts/%s", confbase, name);
	if(access(fname, R_OK))
		fprintf(stderr, "WARNING: cannot read %s\n", fname);

	FILE *f;

#ifndef DISABLE_LEGACY
	rsa_t *rsa_pub = NULL;

	f = fopen(fname, "r");
	if(f) {
		rsa_pub = rsa_read_pem_public_key(f);
		fclose(f);
	}

	if(rsa_priv) {
		if(!rsa_pub) {
			fprintf(stderr, "WARNING: No (usable) public RSA key found.\n");
			if(ask_fix()) {
				FILE *f = fopen(fname, "a");
				if(f) {
					if(rsa_write_pem_public_key(rsa_priv, f))
						fprintf(stderr, "Wrote RSA public key to %s.\n", fname);
					else
						fprintf(stderr, "ERROR: could not write RSA public key to %s.\n", fname);
					fclose(f);
				} else {
					fprintf(stderr, "ERROR: could not append to %s: %s\n", fname, strerror(errno));
				}
			}
		} else {
			// TODO: suggest remedies
			size_t len = rsa_size(rsa_priv);
			if(len != rsa_size(rsa_pub)) {
				fprintf(stderr, "ERROR: public and private RSA keys do not match.\n");
				return 1;
			}
			char buf1[len], buf2[len], buf3[len];
			randomize(buf1, sizeof buf1);
			buf1[0] &= 0x7f;
			memset(buf2, 0, sizeof buf2);
			memset(buf3, 0, sizeof buf2);
			if(!rsa_public_encrypt(rsa_pub, buf1, sizeof buf1, buf2)) {
				fprintf(stderr, "ERROR: public RSA key does not work.\n");
				return 1;
			}
			if(!rsa_private_decrypt(rsa_priv, buf2, sizeof buf2, buf3)) {
				fprintf(stderr, "ERROR: private RSA key does not work.\n");
				return 1;
			}
			if(memcmp(buf1, buf3, sizeof buf1)) {
				fprintf(stderr, "ERROR: public and private RSA keys do not match.\n");
				return 1;
			}
		}
	} else {
		if(rsa_pub)
			fprintf(stderr, "WARNING: A public RSA key was found but no private key is known.\n");
	}
#endif

	ecdsa_t *ecdsa_pub = NULL;

	f = fopen(fname, "r");
	if(f) {
		ecdsa_pub = get_pubkey(f);
		if(!ecdsa_pub) {
			rewind(f);
			ecdsa_pub = ecdsa_read_pem_public_key(f);
		}
		fclose(f);
	}

	if(ecdsa_priv) {
		if(!ecdsa_pub) {
			fprintf(stderr, "WARNING: No (usable) public Ed25519 key found.\n");
			if(ask_fix()) {
				FILE *f = fopen(fname, "a");
				if(f) {
					if(ecdsa_write_pem_public_key(ecdsa_priv, f))
						fprintf(stderr, "Wrote Ed25519 public key to %s.\n", fname);
					else
						fprintf(stderr, "ERROR: could not write Ed25519 public key to %s.\n", fname);
					fclose(f);
				} else {
					fprintf(stderr, "ERROR: could not append to %s: %s\n", fname, strerror(errno));
				}
			}
		} else {
			// TODO: suggest remedies
			char *key1 = ecdsa_get_base64_public_key(ecdsa_pub);
			if(!key1) {
				fprintf(stderr, "ERROR: public Ed25519 key does not work.\n");
				return 1;
			}
			char *key2 = ecdsa_get_base64_public_key(ecdsa_priv);
			if(!key2) {
				free(key1);
				fprintf(stderr, "ERROR: private Ed25519 key does not work.\n");
				return 1;
			}
			int result = strcmp(key1, key2);
			free(key1);
			free(key2);
			if(result) {
				fprintf(stderr, "ERROR: public and private Ed25519 keys do not match.\n");
				return 1;
			}
		}
	} else {
		if(ecdsa_pub)
			fprintf(stderr, "WARNING: A public Ed25519 key was found but no private key is known.\n");
	}

	// Check whether scripts are executable

	struct dirent *ent;
	DIR *dir = opendir(confbase);
	if(!dir) {
		fprintf(stderr, "ERROR: cannot read directory %s: %s\n", confbase, strerror(errno));
		return 1;
	}

	while((ent = readdir(dir))) {
		if(strtailcmp(ent->d_name, "-up") && strtailcmp(ent->d_name, "-down"))
			continue;

		strncpy(fname, ent->d_name, sizeof fname);
		char *dash = strrchr(fname, '-');
		if(!dash)
			continue;
		*dash = 0;

		if(strcmp(fname, "tinc") && strcmp(fname, "host") && strcmp(fname, "subnet")) {
			static bool explained = false;
			fprintf(stderr, "WARNING: Unknown script %s" SLASH "%s found.\n", confbase, ent->d_name);
			if(!explained) {
				fprintf(stderr, "The only scripts in %s executed by tinc are:\n", confbase);
				fprintf(stderr, "tinc-up, tinc-down, host-up, host-down, subnet-up and subnet-down.\n");
				explained = true;
			}
			continue;
		}

		snprintf(fname, sizeof fname, "%s" SLASH "%s", confbase, ent->d_name);
		if(access(fname, R_OK | X_OK)) {
			if(errno != EACCES) {
				fprintf(stderr, "ERROR: cannot access %s: %s\n", fname, strerror(errno));
				continue;
			}
			fprintf(stderr, "WARNING: cannot read and execute %s: %s\n", fname, strerror(errno));
			if(ask_fix()) {
				if(chmod(fname, 0755))
					fprintf(stderr, "ERROR: cannot change permissions on %s: %s\n", fname, strerror(errno));
			}
		}
	}
	closedir(dir);

	snprintf(dname, sizeof dname, "%s" SLASH "hosts", confbase);
	dir = opendir(dname);
	if(!dir) {
		fprintf(stderr, "ERROR: cannot read directory %s: %s\n", dname, strerror(errno));
		return 1;
	}

	while((ent = readdir(dir))) {
		if(strtailcmp(ent->d_name, "-up") && strtailcmp(ent->d_name, "-down"))
			continue;

		strncpy(fname, ent->d_name, sizeof fname);
		char *dash = strrchr(fname, '-');
		if(!dash)
			continue;
		*dash = 0;

		snprintf(fname, sizeof fname, "%s" SLASH "hosts" SLASH "%s", confbase, ent->d_name);
		if(access(fname, R_OK | X_OK)) {
			if(errno != EACCES) {
				fprintf(stderr, "ERROR: cannot access %s: %s\n", fname, strerror(errno));
				continue;
			}
			fprintf(stderr, "WARNING: cannot read and execute %s: %s\n", fname, strerror(errno));
			if(ask_fix()) {
				if(chmod(fname, 0755))
					fprintf(stderr, "ERROR: cannot change permissions on %s: %s\n", fname, strerror(errno));
			}
		}
	}
	closedir(dir);
	
	// Check for obsolete / unsafe / unknown configuration variables.

	check_conffile(tinc_conf, true);

	dir = opendir(dname);
	if(dir) {
		while((ent = readdir(dir))) {
			if(!check_id(ent->d_name))
				continue;

			snprintf(fname, sizeof fname, "%s" SLASH "hosts" SLASH "%s", confbase, ent->d_name);
			check_conffile(fname, false);
		}
		closedir(dir);
	}

	return 0;
}

