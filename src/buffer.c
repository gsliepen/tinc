/*
    buffer.c -- buffer management
    Copyright (C) 2011 Guus Sliepen <guus@tinc-vpn.org>,

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

#include "buffer.h"
#include "xalloc.h"

void buffer_compact(buffer_t *buffer, int maxsize) {
	if(buffer->len >= maxsize || buffer->offset / 7 > buffer->len / 8) {
		memmove(buffer->data, buffer->data + buffer->offset, buffer->len - buffer->offset);
		buffer->len -= buffer->offset;
		buffer->offset = 0;
	}
}

// Make sure we can add size bytes to the buffer, and return a pointer to the start of those bytes.

char *buffer_prepare(buffer_t *buffer, int size) {
	if(!buffer->data) {
		buffer->maxlen = size;
		buffer->data = xmalloc(size);
	} else {
		if(buffer->offset && buffer->len + size > buffer->maxlen) {
			memmove(buffer->data, buffer->data + buffer->offset, buffer->len - buffer->offset);
			buffer->len -= buffer->offset;
			buffer->offset = 0;
		}

		if(buffer->len + size > buffer->maxlen) {
			buffer->maxlen = buffer->len + size;
			buffer->data = xrealloc(buffer->data, buffer->maxlen);
		}
	}

	char *start = buffer->data + buffer->len;

	buffer->len += size;

	return start;
}

// Copy data into the buffer.
			
void buffer_add(buffer_t *buffer, const char *data, int size) {
	memcpy(buffer_prepare(buffer, size), data, size);
}

// Remove given number of bytes from the buffer, return a pointer to the start of them.

static char *buffer_consume(buffer_t *buffer, int size) {
	char *start = buffer->data + buffer->offset;

	buffer->offset += size;

	if(buffer->offset >= buffer->len) {
		buffer->offset = 0;
		buffer->len = 0;
	}

	return start;
}

// Check if there is a complete line in the buffer, and if so, return it NULL-terminated.

char *buffer_readline(buffer_t *buffer) {
	char *newline = memchr(buffer->data + buffer->offset, '\n', buffer->len - buffer->offset);

	if(!newline)
		return NULL;

	int len = newline + 1 - (buffer->data + buffer->offset);
	*newline = 0;
	return buffer_consume(buffer, len);
}

// Check if we have enough bytes in the buffer, and if so, return a pointer to the start of them.

char *buffer_read(buffer_t *buffer, int size) {
	if(buffer->len - buffer->offset < size)
		return NULL;

	return buffer_consume(buffer, size);
}

void buffer_clear(buffer_t *buffer) {
	free(buffer->data);
	buffer->data = NULL;
	buffer->maxlen = 0;
	buffer->len = 0;
	buffer->offset = 0;
}
