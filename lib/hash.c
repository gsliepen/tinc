/*
    hash.c -- Handle hash datastructures
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

    $Id: hash.c,v 1.1 2000/10/20 16:44:32 zarq Exp $
*/

#include "config.h"

/*
  hash_delete
  delete one element, indicated by key, from hash
*/
int hash_delete(hash_t hash, char *key)
{
}

/*
  hash_insert_maybe
  insert an element into the hash, unless an element with the
  same key already exists.
*/
int hash_insert_maybe(hash_t hash, void *data, char *key)
{
  if(hash_retrieve(hash, key))
    {
    }
}

/*
  hash_insert_or_update
  
  If an element indicated by key exists in the hash, update the
  associated pointer.  Otherwise, insert this pointer as a new
  element.
*/
int hash_insert_or_update(hash_t hash, void *data, char *key)
{
  
}

