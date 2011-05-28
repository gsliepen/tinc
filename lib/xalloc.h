#include <sys/types.h>

#ifndef PARAMS
# if defined PROTOTYPES || (defined __STDC__ && __STDC__)
#  define PARAMS(Args) Args
# else
#  define PARAMS(Args) ()
# endif
#endif

/* Exit value when the requested amount of memory is not available.
   The caller may set it to some other value.  */
extern int xalloc_exit_failure;

/* FIXME: describe */
extern char *const xalloc_msg_memory_exhausted;

/* FIXME: describe */
extern void (*xalloc_fail_func) (int);

void *xmalloc PARAMS ((size_t n)) __attribute__ ((__malloc__));
void *xmalloc_and_zero PARAMS ((size_t n)) __attribute__ ((__malloc__));
void *xcalloc PARAMS ((size_t n, size_t s));
void *xrealloc PARAMS ((void *p, size_t n)) __attribute__ ((__malloc__));

char *xstrdup PARAMS ((const char *s)) __attribute__ ((__malloc__));

extern int xasprintf(char **strp, const char *fmt, ...);
extern int xvasprintf(char **strp, const char *fmt, va_list ap);
