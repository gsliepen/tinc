#include "conf_net.h"
#include "logger.h"

bool get_config_subnet(const config_t *cfg, subnet_t **result) {
	subnet_t subnet = {0};

	if(!cfg) {
		return false;
	}

	if(!str2net(&subnet, cfg->value)) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Subnet expected for configuration variable %s in %s line %d",
		       cfg->variable, cfg->file, cfg->line);
		return false;
	}

	if(subnetcheck(subnet)) {
		*(*result = new_subnet()) = subnet;
		return true;
	}

	logger(DEBUG_ALWAYS, LOG_ERR, "Network address and prefix length do not match for configuration variable %s in %s line %d",
	       cfg->variable, cfg->file, cfg->line);
	return false;
}

