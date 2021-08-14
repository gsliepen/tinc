#ifndef TINC_NET_CONF_H
#define TINC_NET_CONF_H

#include "system.h"
#include "conf.h"
#include "subnet.h"

extern bool get_config_subnet(const config_t *config, struct subnet_t **result);

#endif // TINC_NET_CONF_H
