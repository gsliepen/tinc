#ifndef __TINC_BUFFER_H__
#define __TINC_BUFFER_H__

typedef struct buffer_t {
	char *data;
	int maxlen;
	int len;
	int offset;
} buffer_t;

extern void buffer_compact(buffer_t *buffer, int maxsize);
extern char *buffer_prepare(buffer_t *buffer, int size);
extern void buffer_add(buffer_t *buffer, const char *data, int size);
extern char *buffer_readline(buffer_t *buffer);
extern char *buffer_read(buffer_t *buffer, int size);
extern void buffer_clear(buffer_t *buffer);

#endif
