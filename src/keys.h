#ifndef TINC_KEYS_H
#define TINC_KEYS_H

#include "rsa.h"
#include "ecdsa.h"
#include "splay_tree.h"

extern bool disable_old_keys(const char *filename, const char *what);

extern ecdsa_t *read_ecdsa_private_key(splay_tree_t *config_tree, char **keyfile);
extern bool read_ecdsa_public_key(ecdsa_t **ecdsa, splay_tree_t **config_tree, const char *name);

#ifndef DISABLE_LEGACY
extern rsa_t *read_rsa_private_key(splay_tree_t *config, char **keyfile);
extern rsa_t *read_rsa_public_key(splay_tree_t *config_tree, const char *name);
#endif

#endif // TINC_KEYS_H
