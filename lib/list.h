/*
    list.h -- header file for list.c
    Copyright (C) 2000 Ivo Timmermans <itimmermans@bigfoot.com>
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

    $Id: list.h,v 1.1 2000/10/20 16:44:32 zarq Exp $
*/

#ifndef __TINC_LIST_H__
#define __TINC_LIST_H__

typedef struct list_callbacks_t {
  int (*delete) (void *);
} list_callbacks_t;

typedef struct list_node_t {
  void *data;
  struct list_node_t *prev;
  struct list_node_t *next;
} list_node_t;

typedef struct list_t {
  list_node_t *head;
  list_node_t *tail;
  list_callbacks_t *callbacks;
} list_t;



#endif /* __TINC_LIST_H__ */
