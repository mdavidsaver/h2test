
#include <stdlib.h>
#include <ctype.h>

#include <signal.h>

#include <event2/event.h>

#include "util.h"

void fprintf_bytes(FILE *fp, const void *b, size_t l)
{
    const char *buf = b;
    for(;l; l--, buf++) {
        char c = *buf;
        if(isprint(c))
            fputc(c, fp);
        else
            fprintf(fp, "\\x%02x", (int)(c&0xff));
    }
}

typedef struct {
    struct event *int_, *term, *quit;
    struct event_base *base;
} sigevents;

static
void sighandle(evutil_socket_t s, short evt, void *raw)
{
    sigevents *events = raw;
    fprintf(stderr, "Signal.  Breaking\n");
    event_base_loopexit(events->base, NULL);
}

void* setsighandle(struct event_base *base)
{
    sigevents *handle = calloc(1, sizeof(*handle));
    if(handle)
    {
        handle->base = base;
        handle->int_ = evsignal_new(base, SIGINT, sighandle, handle);
        handle->term = evsignal_new(base, SIGTERM, sighandle, handle);
        handle->quit = evsignal_new(base, SIGQUIT, sighandle, handle);
        if(!handle->int_||!handle->term||!handle->quit) {
            fprintf(stderr, "Failed to create some signal handlers\n");
            free(handle);
            return NULL;
        }
        evsignal_add(handle->int_, NULL);
        evsignal_add(handle->term, NULL);
        evsignal_add(handle->quit, NULL);
    }
    return handle;
}

void cancelsighandle(void* raw)
{
    sigevents *events = raw;
    if(!raw) return;
    event_free(events->int_);
    event_free(events->term);
    event_free(events->quit);
    free(events);
}
