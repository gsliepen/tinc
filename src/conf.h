/*
    conf.h -- header for conf.c
    Copyright (C) 1998,1999,2000 Ivo Timmermans <itimmermans@bigfoot.com>
                            2000 Guus Sliepen <guus@sliepen.warande.net>

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

    $Id: conf.h,v 1.6.4.15 2000/10/29 00:24:31 guus Exp $
*/

#ifndef __TINC_CONF_H__
#define __TINC_CONF_H__

#include "net.h"

#define MAXTIMEOUT 900  /* Maximum timeout value for retries. Should this be a configuration option? */

typedef struct ip_mask_t {
  ipv4_t address;
  ipv4_t mask;
} ip_mask_t;

typedef enum which_t {
  tincname = 1,
  connectto,
  pingtimeout,
  tapdevice,
  privatekey,
  keyexpire,
  resolve_dns,
  interface,
  interfaceip,
  address,
  port,
  publickey,
  subnet,
  restricthosts,
  restrictsubnets,
  restrictaddress,
  restrictport,
  indirectdata,
  tcponly,
} which_t;

typedef struct config_t {
  struct config_t *next;
  which_t which;
  int argtype;
  union data {
    unsigned long val;
    void *ptr;
    ip_mask_t *ip;
    struct config_t *next;	/* For nested configs! */
  } data;
} config_t;

typedef struct internal_config_t {
  char *name;
  enum which_t which;
  int argtype;
} internal_config_t;

enum {
  stupid_false = 1,
  stupid_true
};

enum {
  TYPE_NAME = 1,
  TYPE_INT,
  TYPE_IP,
  TYPE_BOOL
};

extern config_t *config;
extern int debug_lvl;
extern int timeout;
extern int sighup;
extern char *confbase;
extern char *netname;

extern config_t *add_config_val(config_t **, int, char *);
extern int read_config_file(config_t **, const char *);
extern const config_t *get_config_val(config_t *, which_t type);
extern void clear_config();
extern int read_server_config(void);

#endif /* __TINC_CONF_H__ */
