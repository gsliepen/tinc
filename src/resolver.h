#ifndef TINC_RESOLVER_H
#define TINC_RESOLVER_H

/*
    resolver.h -- header for resolver.c
    Copyright (C) 2026 euxane

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

typedef struct resolve_t resolve_t;

// Receives the result of a lookup, or NULL if it failed. The callee owns ai.
typedef void (*resolve_cb_t)(void *data, struct addrinfo *ai);

// Resolves host and service in a background thread, without blocking the event loop.
// The callback runs later from the event loop, never from within resolve_start().
// Returns NULL if no lookup could be started; the callback is then never called.
extern resolve_t *resolve_start(const char *host, const char *service, int socktype, resolve_cb_t cb, void *data);

// Prevents the callback of a pending lookup from being called.
extern void resolve_cancel(resolve_t *request);

// Resolves host and service without blocking if both are numeric. Returns NULL otherwise.
extern struct addrinfo *resolve_numeric(const char *host, const char *service, int socktype) ATTR_DEALLOCATOR(freeaddrinfo);

#endif
