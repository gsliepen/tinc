#ifndef TINC_BUFFER_H
#define TINC_BUFFER_H

typedef struct buffer_t {
	char *data;
	uint32_t maxlen;
	uint32_t len;
	uint32_t offset;
} buffer_t;

extern void buffer_compact(buffer_t *buffer, uint32_t maxsize);
extern char *buffer_prepare(buffer_t *buffer, uint32_t size);
extern void buffer_add(buffer_t *buffer, const char *data, uint32_t size);
extern char *buffer_readline(buffer_t *buffer);
extern char *buffer_read(buffer_t *buffer, uint32_t size);
extern void buffer_clear(buffer_t *buffer);

#endif
