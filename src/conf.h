/*
    conf.h -- header for conf.c
    Copyright (C) 1998,99 Ivo Timmermans <zarq@iname.com>

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
*/

#ifndef __TINC_CONF_H__
#define __TINC_CONF_H__

typedef struct ip_mask_t {
  unsigned long ip;
  unsigned long mask;
} ip_mask_t;

typedef union data_t {
  unsigned long val;
  void *ptr;
  ip_mask_t *ip;
} data_t;

typedef enum which_t {
  passphrasesdir = 1,
  upstreamip,
  upstreamport,
  listenport,
  myvpnip,
  tapdevice,
  allowconnect,
  pingtimeout,
  keyexpire,
} which_t;

typedef struct config_t {
  struct config_t *next;
  which_t which;
  data_t data;
} config_t;

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

extern config_t *add_config_val(config_t **, int, char *);
extern int read_config_file(const char *);
extern const config_t *get_config_val(which_t type);

#endif /* __TINC_CONF_H__ */
