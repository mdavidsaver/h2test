
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <signal.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <ctype.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <err.h>

#include <event2/event.h>
#include <event2/dns.h>
#include <event2/buffer.h>
#include <event2/bufferevent.h>

#include <nghttp2/nghttp2.h>

#include "util.h"
#include "h2transport.h"

static struct {
    h2session S; /* must be first */
    unsigned int running:1;
    struct event_base *base;
    struct evdns_base *dns;
    h2stream *stream;
    char *path;
} client;

static
void cleanup_session(h2session *h2sess)
{
    assert(&client.S==h2sess);
    nghttp2_session_del(client.S.h2sess);
    client.S.h2sess = NULL;
    if(client.S.bev) bufferevent_free(client.S.bev);
    client.S.bev = NULL;
    if(client.running)
        event_base_loopexit(client.base, NULL);
}

static
int sockconnect(h2session *h2sess)
{
    nghttp2_option *option;
    nghttp2_session_callbacks *callbacks;

    assert(&client.S==h2sess);
    assert(client.S.h2sess==NULL);

    nghttp2_option_new(&option);
    nghttp2_session_callbacks_new(&callbacks);

    h2session_setup_h2(&client.S, callbacks, option);

    if(nghttp2_session_client_new2(&client.S.h2sess, callbacks, &client.S, option)) {
        fprintf(stderr, "Failed to create client session\n");
        bufferevent_free(client.S.bev);
    } else {
        bufferevent_enable(client.S.bev, EV_READ);

        nghttp2_settings_entry iv[] = {
            {NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, 100},
            {NGHTTP2_SETTINGS_ENABLE_PUSH, 0}
        };
        int rv;

        bufferevent_write(client.S.bev, NGHTTP2_CLIENT_CONNECTION_PREFACE,
                          NGHTTP2_CLIENT_CONNECTION_PREFACE_LEN);

        rv = nghttp2_submit_settings(client.S.h2sess, NGHTTP2_FLAG_NONE, iv,
                                     ARRLEN(iv));
        if (rv != 0) {
            printf("failed to submit settings: %s", nghttp2_strerror(rv));
            cleanup_session(h2sess);
        } else {

            nghttp2_nv hdrs[] = {
                MAKE_NV(":method", "GET"),
                MAKE_NV(":scheme", "http"),
                MAKE_NV(":authority", "localhost"),
                MAKE_NV(":path", "/")};

            client.stream = h2session_request(&client.S,
                                              hdrs, ARRLEN(hdrs));
            if(client.stream==NULL) {
                fprintf(stderr, "Failed to create client stream\n");
                cleanup_session(h2sess);
            } else {

                if(nghttp2_session_send(client.S.h2sess)) {
                    fprintf(stderr, "Failed to flush client stream\n");
                    cleanup_session(h2sess);
                } else
                    printf("Sent request\n");
            }
        }

    }

    nghttp2_session_callbacks_del(callbacks);
    nghttp2_option_del(option);
    return 0;
}

static
int stream_have_header(h2stream *strm, const nghttp2_nv *hdr)
{
    printf("Header: %s: %s\n", hdr->name, hdr->value);
    return 0;
}

static
int stream_have_eoh(h2stream *strm)
{
    printf("Response headers ends\n");
    return 0;
}

static
int stream_have_eoi(h2stream *strm)
{
    printf("Response data ends\n");
    return 0;
}

static
void stream_close(h2stream *strm)
{
    memset(strm, 0, sizeof(*strm));
    free(strm);
    printf("Stream ends\n");
    nghttp2_session_terminate_session(client.S.h2sess, NGHTTP2_NO_ERROR);
    event_base_loopexit(client.base, NULL);
}

static
ssize_t stream_read(h2stream* S, const char *buf, size_t blen)
{
    return blen;
}

static
ssize_t stream_write(h2stream* S, char *buf, size_t blen)
{
    return 0;
}

static
h2stream* buildstream(h2session* sess)
{
    h2stream *strm = calloc(1, sizeof(*strm));
    if(strm) {
        strm->have_header = &stream_have_header;
        strm->have_eoh = &stream_have_eoh;
        strm->have_eoi = &stream_have_eoi;
        strm->close = &stream_close;
        strm->read = &stream_read;
        strm->write = &stream_write;
    }
    return strm;
}

int main(int argc, char *argv[])
{
    if(argc<4)
        return 2;
    /* exe host port path */

    client.base = event_base_new();
    assert(client.base);
    client.dns = evdns_base_new(client.base, 1);
    assert(client.dns);

    client.S.cleanup = &cleanup_session;
    client.S.connect = &sockconnect;
    client.S.build_stream = &buildstream;

    client.S.bev = bufferevent_socket_new(client.base, -1, BEV_OPT_CLOSE_ON_FREE);
    assert(client.S.bev);

    h2session_setup_bev(&client.S);

    if(bufferevent_socket_connect_hostname(client.S.bev, client.dns,
                                           AF_UNSPEC, argv[1], atoi(argv[2])))
    {
        fprintf(stderr, "Failed to start connecting!\n");
    } else {
        client.running = 1;
        event_base_loop(client.base, 0);
        client.running = 0;
    }

    cleanup_session(&client.S);

    evdns_base_free(client.dns, 1);
    event_base_free(client.base);

    memset(&client, 0, sizeof(client));

    return 0;
}
