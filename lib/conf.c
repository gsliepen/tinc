/*
    conf.c -- configuration storage & retrieval code
    Copyright (C) 1998 Robert van der Meulen
                  1998-2002 Ivo Timmermans <ivo@o2w.nl>
                  2000-2002 Guus Sliepen <guus@sliepen.warande.net>
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

    $Id: conf.c,v 1.1 2002/04/28 12:46:25 zarq Exp $
*/

#include "config.h"

#include <ctype.h>
#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>

#include <xalloc.h>
#include <utils.h> /* for cp */
#include <avl_tree.h>

#include "conf.h"
#include "netutl.h" /* for str2address */
#include "logging.h"

#include "system.h"

avl_tree_t *config_tree;

int pingtimeout = 0;             /* seconds before timeout */
char *confbase = NULL;           /* directory in which all config files are */
char *netname = NULL;            /* name of the vpn network */

int config_compare(config_t *a, config_t *b)
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

void init_configuration(avl_tree_t **config_tree)
{
cp
  *config_tree = avl_alloc_tree((avl_compare_t)config_compare, (avl_action_t)free_config);
cp
}

void exit_configuration(avl_tree_t **config_tree)
{
cp
  avl_delete_tree(*config_tree);
  *config_tree = NULL;
cp
}

config_t *new_config(void)
{
  config_t *cfg;
cp
  cfg = (config_t *)xmalloc_and_zero(sizeof(*cfg));

  return cfg;
}

void free_config(config_t *cfg)
{
cp
  if(cfg->variable)
    free(cfg->variable);
  if(cfg->value)
    free(cfg->value);
  if(cfg->file)
    free(cfg->file);
  free(cfg);
cp
}

void config_add(avl_tree_t *config_tree, config_t *cfg)
{
cp
  avl_insert(config_tree, cfg);
cp
}

config_t *lookup_config(avl_tree_t *config_tree, char *variable)
{
  config_t cfg, *found;
cp
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
cp
  node = avl_search_node(config_tree, cfg);

  if(node)
    {
      if(node->next)
        {
          found = (config_t *)node->next->data;
          if(!strcasecmp(found->variable, cfg->variable))
            return found;
        }
    }

  return NULL;
}

int get_config_bool(config_t *cfg, int *result)
{
cp
  if(!cfg)
    return 0;

  if(!strcasecmp(cfg->value, "yes"))
    {
      *result = 1;
      return 1;
    }
  else if(!strcasecmp(cfg->value, "no"))
    {
      *result = 0;
      return 1;
    }

  syslog(LOG_ERR, _("\"yes\" or \"no\" expected for configuration variable %s in %s line %d"),
         cfg->variable, cfg->file, cfg->line);

  return 0;
}

int get_config_int(config_t *cfg, int *result)
{
cp
  if(!cfg)
    return 0;

  if(sscanf(cfg->value, "%d", result) == 1)
    return 1;

  syslog(LOG_ERR, _("Integer expected for configuration variable %s in %s line %d"),
         cfg->variable, cfg->file, cfg->line);
  return 0;
}

int get_config_string(config_t *cfg, char **result)
{
cp
  if(!cfg)
    return 0;

  *result = xstrdup(cfg->value);
  return 1;
}

int get_config_address(config_t *cfg, struct addrinfo **result)
{
  struct addrinfo *ai;
cp
  if(!cfg)
    return 0;

  ai = str2addrinfo(cfg->value, NULL, 0);

  if(ai)
    {
      *result = ai;
      return 1;
    }

  syslog(LOG_ERR, _("Hostname or IP address expected for configuration variable %s in %s line %d"),
         cfg->variable, cfg->file, cfg->line);
  return 0;
}

int get_config_port(config_t *cfg, port_t *result)
{
cp
  if(!cfg)
    return 0;

  if(sscanf(cfg->value, "%hu", result) == 1)
    {
      *result = htons(*result);
      return 1;
    }

  syslog(LOG_ERR, _("Port number expected for configuration variable %s in %s line %d"),
         cfg->variable, cfg->file, cfg->line);
  return 0;
}

int get_config_subnet(config_t *cfg, subnet_t **result)
{
  subnet_t *subnet;
cp
  if(!cfg)
    return 0;

  subnet = str2net(cfg->value);

  if(!subnet)
    {
      syslog(LOG_ERR, _("Subnet expected for configuration variable %s in %s line %d"),
             cfg->variable, cfg->file, cfg->line);
      return 0;
    }

  /* Teach newbies what subnets are... */

  if(((subnet->type == SUBNET_IPV4) && maskcheck((char *)&subnet->net.ipv4.address, subnet->net.ipv4.prefixlength, sizeof(ipv4_t)))
     || ((subnet->type == SUBNET_IPV6) && maskcheck((char *)&subnet->net.ipv6.address, subnet->net.ipv6.prefixlength, sizeof(ipv6_t))))
    {
      syslog(LOG_ERR, _("Network address and prefix length do not match for configuration variable %s in %s line %d"),
             cfg->variable, cfg->file, cfg->line);
      free(subnet);
      return 0;
    }

  *result = subnet;

  return 1;
}

