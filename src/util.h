#ifndef H2_UTIL_H
#define H2_UTIL_H

#include <stdio.h>

#define ARRLEN(x) (sizeof(x) / sizeof(x[0]))

#define MAKE_NV(NAME, VALUE)                                                   \
  {                                                                            \
    (uint8_t *) NAME, (uint8_t *)VALUE, sizeof(NAME) - 1, sizeof(VALUE) - 1,   \
        NGHTTP2_NV_FLAG_NONE                                                   \
  }

struct event_base;

void fprintf_bytes(FILE *fp, const void *b, size_t l);

void* setsighandle(struct event_base*);
void cancelsighandle(void*);

#endif /* H2_UTIL_H */
