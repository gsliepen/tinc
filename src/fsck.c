/*
    fsck.c -- Check the configuration files for problems
    Copyright (C) 2014-2022 Guus Sliepen <guus@tinc-vpn.org>

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
#include "xalloc.h"
#include "keys.h"
#include "conf.h"

static const char *exe_name = NULL;

static bool ask_fix(void) {
	if(force) {
		return true;
	}

	if(!tty) {
		return false;
	}

again:
	fprintf(stderr, "Fix y/n? ");
	char buf[1024];

	if(!fgets(buf, sizeof(buf), stdin)) {
		tty = false;
		return false;
	}

	if(buf[0] == 'y' || buf[0] == 'Y') {
		return true;
	}

	if(buf[0] == 'n' || buf[0] == 'N') {
		return false;
	}

	goto again;
}

static void print_tinc_cmd(const char *format, ...) ATTR_FORMAT(printf, 1, 2);
static void print_tinc_cmd(const char *format, ...) {
	if(confbasegiven) {
		fprintf(stderr, "%s -c %s ", exe_name, confbase);
	} else if(netname) {
		fprintf(stderr, "%s -n %s ", exe_name, netname);
	} else {
		fprintf(stderr, "%s ", exe_name);
	}

	va_list va;
	va_start(va, format);
	vfprintf(stderr, format, va);
	va_end(va);
	fputc('\n', stderr);
}

typedef enum {
	KEY_RSA,
	KEY_ED25519,
	KEY_BOTH,
} key_type_t;

static void print_new_keys_cmd(key_type_t key_type, const char *message) {
	fprintf(stderr, "%s\n\n", message);

	switch(key_type) {
	case KEY_RSA:
		fprintf(stderr, "You can generate a new RSA keypair with:\n\n");
		print_tinc_cmd("generate-rsa-keys");
		break;

	case KEY_ED25519:
		fprintf(stderr, "You can generate a new Ed25519 keypair with:\n\n");
		print_tinc_cmd("generate-ed25519-keys");
		break;

	case KEY_BOTH:
		fprintf(stderr, "You can generate new keys with:\n\n");
		print_tinc_cmd("generate-keys");
		break;
	}
}

static int strtailcmp(const char *str, const char *tail) {
	size_t slen = strlen(str);
	size_t tlen = strlen(tail);

	if(tlen > slen) {
		return -1;
	}

	return memcmp(str + slen - tlen, tail, tlen);
}

static void check_conffile(const char *nodename, bool server) {
	splay_tree_t config;
	init_configuration(&config);

	bool read;

	if(server) {
		read = read_server_config(&config);
	} else {
		read = read_host_config(&config, nodename, true);
	}

	if(!read) {
		splay_empty_tree(&config);
		return;
	}

	size_t total_vars = 0;

	while(variables[total_vars].name) {
		++total_vars;
	}

	if(!total_vars) {
		splay_empty_tree(&config);
		return;
	}

	const size_t countlen = total_vars * sizeof(int);
	int *count = alloca(countlen);
	memset(count, 0, countlen);

	for splay_each(config_t, conf, &config) {
		int var_type = 0;

		for(size_t i = 0; variables[i].name; ++i) {
			if(strcasecmp(variables[i].name, conf->variable) == 0) {
				count[i]++;
				var_type = variables[i].type;
			}
		}

		if(var_type == 0) {
			continue;
		}

		if(var_type & VAR_OBSOLETE) {
			fprintf(stderr, "WARNING: obsolete variable %s in %s line %d\n",
			        conf->variable, conf->file, conf->line);
		}

		if(server && !(var_type & VAR_SERVER)) {
			fprintf(stderr, "WARNING: host variable %s found in server config %s line %d \n",
			        conf->variable, conf->file, conf->line);
		}

		if(!server && !(var_type & VAR_HOST)) {
			fprintf(stderr, "WARNING: server variable %s found in host config %s line %d \n",
			        conf->variable, conf->file, conf->line);
		}
	}

	for(size_t i = 0; i < total_vars; ++i) {
		if(count[i] > 1 && !(variables[i].type & VAR_MULTIPLE)) {
			fprintf(stderr, "WARNING: multiple instances of variable %s in %s\n",
			        variables[i].name, nodename ? nodename : "tinc.conf");
		}
	}

	splay_empty_tree(&config);
}

#ifdef HAVE_WINDOWS
typedef int uid_t;

static uid_t getuid(void) {
	return 0;
}

static void check_key_file_mode(const char *fname) {
	(void)fname;
}
#else
static void check_key_file_mode(const char *fname) {
	const uid_t uid = getuid();
	struct stat st;

	if(stat(fname, &st)) {
		fprintf(stderr, "ERROR: could not stat private key file %s\n", fname);
		return;
	}

	if(st.st_mode & 077) {
		fprintf(stderr, "WARNING: unsafe file permissions on %s.\n", fname);

		if(st.st_uid != uid) {
			fprintf(stderr, "You are not running %s as the same uid as %s.\n", exe_name, fname);
		} else if(ask_fix()) {
			if(chmod(fname, st.st_mode & ~077u)) {
				fprintf(stderr, "ERROR: could not change permissions of %s: %s\n", fname, strerror(errno));
			} else {
				fprintf(stderr, "Fixed permissions of %s.\n", fname);
			}
		}
	}
}
#endif // HAVE_WINDOWS

static char *read_node_name(void) {
	if(access(tinc_conf, R_OK) == 0) {
		return get_my_name(true);
	}

	fprintf(stderr, "ERROR: cannot read %s: %s\n", tinc_conf, strerror(errno));

	if(errno == ENOENT) {
		fprintf(stderr, "No tinc configuration found. Create a new one with:\n\n");
		print_tinc_cmd("init");
		return NULL;
	}

	if(errno == EACCES) {
		uid_t uid = getuid();

		if(uid != 0) {
			fprintf(stderr, "You are currently not running tinc as root. Use sudo?\n");
		} else {
			fprintf(stderr, "Check the permissions of each component of the path %s.\n", tinc_conf);
		}
	}

	return NULL;
}

static bool build_host_conf_path(char *fname, const size_t len) {
	char *name = get_my_name(true);

	if(!name) {
		fprintf(stderr, "ERROR: tinc cannot run without a valid Name.\n");
		return false;
	}

	snprintf(fname, len, "%s/hosts/%s", confbase, name);
	free(name);
	return true;
}

static bool ask_fix_ec_public_key(const char *fname, ecdsa_t *ec_priv) {
	if(!ask_fix()) {
		return true;
	}

	if(!disable_old_keys(fname, "public Ed25519 key")) {
		return false;
	}

	FILE *f = fopen(fname, "a");

	if(!f) {
		fprintf(stderr, "ERROR: could not append to %s: %s\n", fname, strerror(errno));
		return false;
	}

	bool success = ecdsa_write_pem_public_key(ec_priv, f);
	fclose(f);

	if(success) {
		fprintf(stderr, "Wrote Ed25519 public key to %s.\n", fname);
	} else {
		fprintf(stderr, "ERROR: could not write Ed25519 public key to %s.\n", fname);
	}

	return success;
}

#ifndef DISABLE_LEGACY
static bool ask_fix_rsa_public_key(const char *fname, rsa_t *rsa_priv) {
	if(!ask_fix()) {
		return true;
	}

	if(!disable_old_keys(fname, "public RSA key")) {
		return false;
	}

	FILE *f = fopen(fname, "a");

	if(!f) {
		fprintf(stderr, "ERROR: could not append to %s: %s\n", fname, strerror(errno));
		return false;
	}

	bool success = rsa_write_pem_public_key(rsa_priv, f);
	fclose(f);

	if(success) {
		fprintf(stderr, "Wrote RSA public key to %s.\n", fname);
	} else {
		fprintf(stderr, "ERROR: could not write RSA public key to %s.\n", fname);
	}

	return success;
}

static bool test_rsa_keypair(rsa_t *rsa_priv, rsa_t *rsa_pub, const char *host_file) {
	size_t len = rsa_size(rsa_priv);

	if(len != rsa_size(rsa_pub)) {
		fprintf(stderr, "ERROR: public and private RSA key lengths do not match.\n");
		return false;
	}

	bool success = false;
	uint8_t *plaintext = xmalloc(len);
	uint8_t *encrypted = xzalloc(len);
	uint8_t *decrypted = xzalloc(len);

	prng_randomize(plaintext, len);
	plaintext[0] &= 0x7f;

	if(rsa_public_encrypt(rsa_pub, plaintext, len, encrypted)) {
		if(rsa_private_decrypt(rsa_priv, encrypted, len, decrypted)) {
			if(memcmp(plaintext, decrypted, len) == 0) {
				success = true;
			} else {
				fprintf(stderr, "ERROR: public and private RSA keys do not match.\n");
				success = ask_fix_rsa_public_key(host_file, rsa_priv);
			}
		} else {
			print_new_keys_cmd(KEY_RSA, "ERROR: private RSA key does not work.");
		}
	} else {
		fprintf(stderr, "ERROR: public RSA key does not work.\n");
		success = ask_fix_rsa_public_key(host_file, rsa_priv);
	}

	free(decrypted);
	free(encrypted);
	free(plaintext);

	return success;
}

static bool check_rsa_pubkey(rsa_t *rsa_priv, rsa_t *rsa_pub, const char *host_file) {
	if(!rsa_pub) {
		fprintf(stderr, "WARNING: No (usable) public RSA key found.\n");
		return ask_fix_rsa_public_key(host_file, rsa_priv);
	}

	if(!rsa_priv) {
		fprintf(stderr, "WARNING: A public RSA key was found but no private key is known.\n");
		return true;
	}

	return test_rsa_keypair(rsa_priv, rsa_pub, host_file);
}
#endif // DISABLE_LEGACY

static bool test_ec_keypair(ecdsa_t *ec_priv, ecdsa_t *ec_pub, const char *host_file) {
	// base64-encoded public key obtained from the PRIVATE key.
	char *b64_priv_pub = ecdsa_get_base64_public_key(ec_priv);

	if(!b64_priv_pub) {
		print_new_keys_cmd(KEY_ED25519, "ERROR: private Ed25519 key does not work.");
		return false;
	}

	// base64-encoded public key obtained from the PUBLIC key.
	char *b64_pub_pub = ecdsa_get_base64_public_key(ec_pub);

	if(!b64_pub_pub) {
		fprintf(stderr, "ERROR: public Ed25519 key does not work.\n");
		free(b64_priv_pub);
		return ask_fix_ec_public_key(host_file, ec_priv);
	}

	bool match = strcmp(b64_pub_pub, b64_priv_pub) == 0;
	free(b64_pub_pub);
	free(b64_priv_pub);

	if(match) {
		return true;
	}

	fprintf(stderr, "ERROR: public and private Ed25519 keys do not match.\n");
	return ask_fix_ec_public_key(host_file, ec_priv);
}

static bool check_ec_pubkey(ecdsa_t *ec_priv, ecdsa_t *ec_pub, const char *host_file) {
	if(!ec_priv) {
		if(ec_pub) {
			print_new_keys_cmd(KEY_ED25519, "WARNING: A public Ed25519 key was found but no private key is known.");
		}

		return true;
	}

	if(ec_pub) {
		return test_ec_keypair(ec_priv, ec_pub, host_file);
	}

	fprintf(stderr, "WARNING: No (usable) public Ed25519 key found.\n");
	return ask_fix_ec_public_key(host_file, ec_priv);
}

static bool check_config_mode(const char *fname) {
	if(access(fname, R_OK | X_OK) == 0) {
		return true;
	}

	if(errno != EACCES) {
		fprintf(stderr, "ERROR: cannot access %s: %s\n", fname, strerror(errno));
		return false;
	}

	fprintf(stderr, "WARNING: cannot read and execute %s: %s\n", fname, strerror(errno));

	if(ask_fix()) {
		if(chmod(fname, 0755)) {
			fprintf(stderr, "ERROR: cannot change permissions on %s: %s\n", fname, strerror(errno));
		}
	}

	return true;
}

static bool check_script_confdir(void) {
	char fname[PATH_MAX];
	DIR *dir = opendir(confbase);

	if(!dir) {
		fprintf(stderr, "ERROR: cannot read directory %s: %s\n", confbase, strerror(errno));
		return false;
	}

	struct dirent *ent;

	while((ent = readdir(dir))) {
		if(strtailcmp(ent->d_name, "-up") && strtailcmp(ent->d_name, "-down")) {
			continue;
		}

		strncpy(fname, ent->d_name, sizeof(fname));
		char *dash = strrchr(fname, '-');

		if(!dash) {
			continue;
		}

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

		snprintf(fname, sizeof(fname), "%s" SLASH "%s", confbase, ent->d_name);
		check_config_mode(fname);
	}

	closedir(dir);

	return true;
}

static bool check_script_hostdir(const char *host_dir) {
	char fname[PATH_MAX];
	DIR *dir = opendir(host_dir);

	if(!dir) {
		fprintf(stderr, "ERROR: cannot read directory %s: %s\n", host_dir, strerror(errno));
		return false;
	}

	struct dirent *ent;

	while((ent = readdir(dir))) {
		if(strtailcmp(ent->d_name, "-up") && strtailcmp(ent->d_name, "-down")) {
			continue;
		}

		strncpy(fname, ent->d_name, sizeof(fname));
		char *dash = strrchr(fname, '-');

		if(!dash) {
			continue;
		}

		*dash = 0;

		snprintf(fname, sizeof(fname), "%s" SLASH "hosts" SLASH "%s", confbase, ent->d_name);
		check_config_mode(fname);
	}

	closedir(dir);

	return true;
}

#ifdef DISABLE_LEGACY
static bool check_public_keys(splay_tree_t *config, const char *name, ecdsa_t *ec_priv) {
#else
static bool check_public_keys(splay_tree_t *config, const char *name, rsa_t *rsa_priv, ecdsa_t *ec_priv) {
#endif
	// Check public keys.
	char host_file[PATH_MAX];

	if(!build_host_conf_path(host_file, sizeof(host_file))) {
		return false;
	}

	if(access(host_file, R_OK)) {
		fprintf(stderr, "WARNING: cannot read %s\n", host_file);
	}

	ecdsa_t *ec_pub = read_ecdsa_public_key(&config, name);

	bool success = true;
#ifndef DISABLE_LEGACY
	rsa_t *rsa_pub = read_rsa_public_key(config, name);
	success = check_rsa_pubkey(rsa_priv, rsa_pub, host_file);
	rsa_free(rsa_pub);
#endif

	if(!check_ec_pubkey(ec_priv, ec_pub, host_file)) {
		success = false;
	}

	ecdsa_free(ec_pub);

	return success;
}

static bool check_keypairs(splay_tree_t *config, const char *name) {
	// Check private keys.
	char *priv_keyfile = NULL;
	ecdsa_t *ec_priv = read_ecdsa_private_key(config, &priv_keyfile);

	if(priv_keyfile) {
		check_key_file_mode(priv_keyfile);
		free(priv_keyfile);
		priv_keyfile = NULL;
	}

#ifdef DISABLE_LEGACY

	if(!ec_priv) {
		print_new_keys_cmd(KEY_ED25519, "ERROR: No Ed25519 private key found.");
		return false;
	}

#else
	rsa_t *rsa_priv = read_rsa_private_key(config, &priv_keyfile);

	if(priv_keyfile) {
		check_key_file_mode(priv_keyfile);
		free(priv_keyfile);
	}

	if(!rsa_priv && !ec_priv) {
		print_new_keys_cmd(KEY_BOTH, "ERROR: Neither RSA or Ed25519 private key found.");
		return false;
	}

#endif

#ifdef DISABLE_LEGACY
	bool success = check_public_keys(config, name, ec_priv);
#else
	bool success = check_public_keys(config, name, rsa_priv, ec_priv);
	rsa_free(rsa_priv);
#endif
	ecdsa_free(ec_priv);

	return success;
}

static void check_config_variables(const char *host_dir) {
	check_conffile(NULL, true);

	DIR *dir = opendir(host_dir);

	if(dir) {
		for(struct dirent * ent; (ent = readdir(dir));) {
			if(check_id(ent->d_name)) {
				check_conffile(ent->d_name, false);
			}
		}

		closedir(dir);
	}
}

static bool check_scripts_and_configs(void) {
	// Check whether scripts are executable.
	if(!check_script_confdir()) {
		return false;
	}

	char host_dir[PATH_MAX];
	snprintf(host_dir, sizeof(host_dir), "%s" SLASH "hosts", confbase);

	if(!check_script_hostdir(host_dir)) {
		return false;
	}

	// Check for obsolete / unsafe / unknown configuration variables (and print warnings).
	check_config_variables(host_dir);

	return true;
}

int fsck(const char *argv0) {
	exe_name = argv0;

	// Check that tinc.conf is readable and read our name if it is.
	char *name = read_node_name();

	if(!name) {
		fprintf(stderr, "ERROR: tinc cannot run without a valid Name.\n");
		exe_name = NULL;
		return EXIT_FAILURE;
	}

	// Avoid touching global configuration here. Read the config files into
	// a temporary configuration tree, then throw it away after fsck is done.
	splay_tree_t config;
	init_configuration(&config);

	// Read the server configuration file and append host configuration for our node.
	bool success = read_server_config(&config) &&
	               read_host_config(&config, name, true);

	// Check both RSA and EC key pairs.
	// We need working configuration to run this check.
	if(success) {
		success = check_keypairs(&config, name);
	}

	// Check that scripts are executable and check the config for invalid variables.
	// This check does not require working configuration, so run it always.
	// This way, we can diagnose more issues on the first run.
	success = success & check_scripts_and_configs();

	splay_empty_tree(&config);
	free(name);
	exe_name = NULL;

	return success ? EXIT_SUCCESS : EXIT_FAILURE;
}
