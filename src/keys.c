#include "system.h"
#include "keys.h"
#include "conf.h"
#include "logger.h"
#include "names.h"
#include "xalloc.h"
#include "ecdsa.h"
#include "fs.h"

bool disable_old_keys(const char *filename, const char *what) {
	char tmpfile[PATH_MAX] = "";
	char buf[1024];
	bool disabled = false;
	bool block = false;
	bool error = false;

	FILE *r = fopen(filename, "r");
	FILE *w = NULL;

	if(!r) {
		return false;
	}

	size_t result = snprintf(tmpfile, sizeof(tmpfile), "%s.tmp", filename);

	if(result < sizeof(tmpfile)) {
		struct stat st = {.st_mode = 0600};
		fstat(fileno(r), &st);
		w = fopenmask(tmpfile, "w", st.st_mode);
	}

	while(fgets(buf, sizeof(buf), r)) {
		if(!block && !strncmp(buf, "-----BEGIN ", 11)) {
			if((strstr(buf, " ED25519 ") && strstr(what, "Ed25519")) || (strstr(buf, " RSA ") && strstr(what, "RSA"))) {
				disabled = true;
				block = true;
			}
		}

		bool ed25519pubkey = !strncasecmp(buf, "Ed25519PublicKey", 16) && strchr(" \t=", buf[16]) && strstr(what, "Ed25519");

		if(ed25519pubkey) {
			disabled = true;
		}

		if(w) {
			if(block || ed25519pubkey) {
				fputc('#', w);
			}

			if(fputs(buf, w) < 0) {
				error = true;
				break;
			}
		}

		if(block && !strncmp(buf, "-----END ", 9)) {
			block = false;
		}
	}

	if(w)
		if(fclose(w) < 0) {
			error = true;
		}

	if(ferror(r) || fclose(r) < 0) {
		error = true;
	}

	if(disabled) {
		if(!w || error) {
			fprintf(stderr, "Warning: old key(s) found, remove them by hand!\n");

			if(w) {
				unlink(tmpfile);
			}

			return false;
		}

#ifdef HAVE_WINDOWS
		// We cannot atomically replace files on Windows.
		char bakfile[PATH_MAX] = "";
		snprintf(bakfile, sizeof(bakfile), "%s.bak", filename);

		if(rename(filename, bakfile) || rename(tmpfile, filename)) {
			rename(bakfile, filename);
#else

		if(rename(tmpfile, filename)) {
#endif
			fprintf(stderr, "Warning: old key(s) found, remove them by hand!\n");
			unlink(tmpfile);
			return false;
		}

#ifdef HAVE_WINDOWS
		unlink(bakfile);
#endif
		fprintf(stderr, "Warning: old key(s) found and disabled.\n");
	}

	unlink(tmpfile);
	return true;
}

ecdsa_t *read_ecdsa_private_key(splay_tree_t *config_tree, char **keyfile) {
	FILE *fp;
	char *fname;

	/* Check for PrivateKeyFile statement and read it */

	if(!get_config_string(lookup_config(config_tree, "Ed25519PrivateKeyFile"), &fname)) {
		xasprintf(&fname, "%s" SLASH "ed25519_key.priv", confbase);
	}

	fp = fopen(fname, "r");

	if(!fp) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Error reading Ed25519 private key file `%s': %s", fname, strerror(errno));

		if(errno == ENOENT) {
			logger(DEBUG_ALWAYS, LOG_INFO, "Create an Ed25519 key pair with `tinc -n %s generate-ed25519-keys'.", netname ? netname : ".");
		}

		free(fname);
		return NULL;
	}

#ifndef HAVE_WINDOWS
	struct stat s;

	if(fstat(fileno(fp), &s)) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Could not stat Ed25519 private key file `%s': %s'", fname, strerror(errno));
		free(fname);
		fclose(fp);
		return false;
	}

	if(s.st_mode & ~0100700u) {
		logger(DEBUG_ALWAYS, LOG_WARNING, "Warning: insecure file permissions for Ed25519 private key file `%s'!", fname);
	}

#endif

	ecdsa_t *key = ecdsa_read_pem_private_key(fp);
	fclose(fp);

	if(!key) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Reading Ed25519 private key file `%s' failed", fname);
		free(fname);
		return NULL;
	}

	if(keyfile) {
		*keyfile = fname;
	} else {
		free(fname);
	}

	return key;
}

ecdsa_t *read_ecdsa_public_key(splay_tree_t **config_tree, const char *name) {
	FILE *fp;
	char *fname;
	char *p;

	if(!*config_tree) {
		*config_tree = create_configuration();

		if(!read_host_config(*config_tree, name, true)) {
			return NULL;
		}
	}

	/* First, check for simple Ed25519PublicKey statement */

	if(get_config_string(lookup_config(*config_tree, "Ed25519PublicKey"), &p)) {
		ecdsa_t *ecdsa = ecdsa_set_base64_public_key(p);
		free(p);
		return ecdsa;
	}

	/* Else, check for Ed25519PublicKeyFile statement and read it */

	if(!get_config_string(lookup_config(*config_tree, "Ed25519PublicKeyFile"), &fname)) {
		xasprintf(&fname, "%s" SLASH "hosts" SLASH "%s", confbase, name);
	}

	fp = fopen(fname, "r");

	if(!fp) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Error reading Ed25519 public key file `%s': %s",
		       fname, strerror(errno));
		free(fname);
		return NULL;
	}

	ecdsa_t *ecdsa = ecdsa_read_pem_public_key(fp);

	if(!ecdsa && errno != ENOENT) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Parsing Ed25519 public key file `%s' failed.", fname);
	}

	fclose(fp);
	free(fname);

	return ecdsa;
}

#ifndef DISABLE_LEGACY
rsa_t *read_rsa_private_key(splay_tree_t *config_tree, char **keyfile) {
	FILE *fp;
	char *fname;
	char *n, *d;
	rsa_t *key;

	/* First, check for simple PrivateKey statement */

	config_t *rsa_priv_conf = lookup_config(config_tree, "PrivateKey");

	if(get_config_string(rsa_priv_conf, &d)) {
		if(!get_config_string(lookup_config(config_tree, "PublicKey"), &n)) {
			logger(DEBUG_ALWAYS, LOG_ERR, "PrivateKey used but no PublicKey found!");
			free_string(d);
			return NULL;
		}

		key = rsa_set_hex_private_key(n, "FFFF", d);
		free(n);
		free_string(d);

		if(key && keyfile && rsa_priv_conf->file) {
			*keyfile = xstrdup(rsa_priv_conf->file);
		}

		return key;
	}

	/* Else, check for PrivateKeyFile statement and read it */

	if(!get_config_string(lookup_config(config_tree, "PrivateKeyFile"), &fname)) {
		xasprintf(&fname, "%s" SLASH "rsa_key.priv", confbase);
	}

	fp = fopen(fname, "r");

	if(!fp) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Error reading RSA private key file `%s': %s",
		       fname, strerror(errno));

		if(errno == ENOENT) {
			logger(DEBUG_ALWAYS, LOG_INFO, "Create an RSA key pair with `tinc -n %s generate-rsa-keys'.", netname ? netname : ".");
		}

		free(fname);
		return NULL;
	}

#ifndef HAVE_WINDOWS
	struct stat s;

	if(fstat(fileno(fp), &s)) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Could not stat RSA private key file `%s': %s'", fname, strerror(errno));
		free(fname);
		fclose(fp);
		return NULL;
	}

	if(s.st_mode & ~0100700u) {
		logger(DEBUG_ALWAYS, LOG_WARNING, "Warning: insecure file permissions for RSA private key file `%s'!", fname);
	}

#endif

	key = rsa_read_pem_private_key(fp);
	fclose(fp);

	if(!key) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Reading RSA private key file `%s' failed: %s", fname, strerror(errno));
		free(fname);
		return NULL;
	}

	if(keyfile) {
		*keyfile = fname;
	} else {
		free(fname);
	}

	return key;
}

rsa_t *read_rsa_public_key(splay_tree_t *config_tree, const char *name) {
	FILE *fp;
	char *fname;
	char *n;

	/* First, check for simple PublicKey statement */

	if(get_config_string(lookup_config(config_tree, "PublicKey"), &n)) {
		rsa_t *rsa = rsa_set_hex_public_key(n, "FFFF");
		free(n);
		return rsa;
	}

	/* Else, check for PublicKeyFile statement and read it */

	if(!get_config_string(lookup_config(config_tree, "PublicKeyFile"), &fname)) {
		xasprintf(&fname, "%s" SLASH "hosts" SLASH "%s", confbase, name);
	}

	fp = fopen(fname, "r");

	if(!fp) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Error reading RSA public key file `%s': %s", fname, strerror(errno));
		free(fname);
		return NULL;
	}

	rsa_t *rsa = rsa_read_pem_public_key(fp);
	fclose(fp);

	if(!rsa) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Reading RSA public key file `%s' failed: %s", fname, strerror(errno));
	}

	free(fname);

	return rsa;
}
#endif
