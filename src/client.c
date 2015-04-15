
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

static struct {
    unsigned int running:1;
    struct event_base *base;
    struct evdns_base *dns;
    struct bufferevent *bev;
    nghttp2_session *h2sess;
    int32_t streamid;
    char *path;
} client;

static
void cleanup_session(void)
{
    nghttp2_session_del(client.h2sess);
    bufferevent_free(client.bev);
    if(client.running)
        event_base_loopexit(client.base, NULL);
}
static
int response_begin(nghttp2_session *h2sess,
                  const nghttp2_frame *frame,
                  void *raw)
{
    printf("Response headers begin\n");
    return 0;
}

static
int response_end(nghttp2_session *h2sess, int32_t streamid,
                uint32_t error_code, void *raw)
{
    printf("Response ends\n");
    nghttp2_session_terminate_session(client.h2sess, NGHTTP2_NO_ERROR);
    event_base_loopexit(client.base, NULL);
    return 0;
}

static
int on_header_callback(nghttp2_session *session,
                       const nghttp2_frame *frame, const uint8_t *name,
                       size_t namelen, const uint8_t *value,
                       size_t valuelen, uint8_t flags,
                       void *user_data)
{
    printf("Header: %s: %s\n", name, value);
    return 0;
}

static int on_frame_recv_callback(nghttp2_session *session,
                                  const nghttp2_frame *frame, void *user_data)
{

    if(frame->hd.type==NGHTTP2_HEADERS && frame->hd.flags & NGHTTP2_FLAG_END_HEADERS) {
        printf("End of headers\n");
    }
    return 0;
}

/* move data from nghttp2's send queue into bufferevent's TX queue */
static
ssize_t send_sess_data(nghttp2_session *h2sess,
                       const uint8_t *data, size_t length,
                       int flags, void *raw)
{
    struct evbuffer *buf = bufferevent_get_output(client.bev);

    assert(client.h2sess==h2sess);

    if(evbuffer_add(buf, data, length)) {
        fprintf(stderr, "send_sess_data error\n");
        return NGHTTP2_ERR_CALLBACK_FAILURE;
    }

    printf("Tx %lu '", (unsigned long)length);
    fprintf_bytes(stdout, data, length);
    printf("'\n");
    return length;
}

/* Move data from bufferevent's RX queue to the NGHTTP2 sesssions input queue */
static
void sockread(struct bufferevent *bev, void *raw)
{
    struct evbuffer *buf = bufferevent_get_input(bev);
    size_t blen = evbuffer_get_length(buf);
    unsigned char *cbuf = evbuffer_pullup(buf, -1);
    ssize_t ret;

    assert(client.h2sess);

    if(!cbuf) {
        fprintf(stderr, "buf too long! %lu\n", (unsigned long)blen);
        return;
    }

    ret = nghttp2_session_mem_recv(client.h2sess, cbuf, blen);
    printf("Rx %lu '", (unsigned long)blen);
    fprintf_bytes(stdout, cbuf, blen);
    printf("'\n");
    evbuffer_drain(buf, blen);

    if(ret<0) {
        fprintf(stderr, "recv error %s\n", nghttp2_strerror(ret));
        cleanup_session();
        return;

    }
    if(nghttp2_session_send(client.h2sess)) {
        fprintf(stderr, "send after recv error\n");
        cleanup_session();
    }
}

static
void sockevent(struct bufferevent *bev, short what, void *raw)
{
    if(what&BEV_EVENT_CONNECTED) {
        printf("Connected\n");
        nghttp2_option *option;
        nghttp2_session_callbacks *callbacks;

        nghttp2_option_new(&option);
        nghttp2_session_callbacks_new(&callbacks);

        nghttp2_option_set_recv_client_preface(option, 1);

        nghttp2_session_callbacks_set_send_callback(callbacks, send_sess_data);

        nghttp2_session_callbacks_set_on_frame_recv_callback(callbacks, on_frame_recv_callback);
        nghttp2_session_callbacks_set_on_begin_headers_callback(callbacks, response_begin);
        nghttp2_session_callbacks_set_on_header_callback(callbacks, on_header_callback);
        nghttp2_session_callbacks_set_on_stream_close_callback(callbacks, response_end);

        if(nghttp2_session_client_new2(&client.h2sess, callbacks, NULL, option)) {
            fprintf(stderr, "Failed to create client session\n");
            bufferevent_free(client.bev);
        } else {
            bufferevent_enable(client.bev, EV_READ);

            nghttp2_settings_entry iv[] = {
                {NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, 100},
                {NGHTTP2_SETTINGS_ENABLE_PUSH, 0}
            };
            int rv;

            bufferevent_write(client.bev, NGHTTP2_CLIENT_CONNECTION_PREFACE,
                              NGHTTP2_CLIENT_CONNECTION_PREFACE_LEN);

            rv = nghttp2_submit_settings(client.h2sess, NGHTTP2_FLAG_NONE, iv,
                                         ARRLEN(iv));
            if (rv != 0) {
                printf("failed to submit settings: %s", nghttp2_strerror(rv));
                cleanup_session();
            } else {

                nghttp2_nv hdrs[] = {
                    MAKE_NV(":method", "GET"),
                    MAKE_NV(":scheme", "http"),
                    MAKE_NV(":authority", "localhost"),
                    MAKE_NV(":path", "/")};

                client.streamid = nghttp2_submit_request(client.h2sess, NULL,
                                                         hdrs, ARRLEN(hdrs),
                                                         NULL, NULL);
                if(client.streamid<0) {
                    fprintf(stderr, "Failed to create client stream\n");
                    cleanup_session();
                } else {

                    if(nghttp2_session_send(client.h2sess)) {
                        fprintf(stderr, "Failed to flush client stream\n");
                        cleanup_session();
                    } else
                        printf("Sent request\n");
                }
            }

        }

        nghttp2_session_callbacks_del(callbacks);
        nghttp2_option_del(option);

    } else {
        if(what&BEV_EVENT_ERROR) {
            printf("Client error\n");
        }
        if(what&BEV_EVENT_TIMEOUT) {
            printf("Client timeout\n");
        }
        printf("Client close\n");
        cleanup_session();
    }
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

    client.bev = bufferevent_socket_new(client.base, -1, BEV_OPT_CLOSE_ON_FREE);
    assert(client.bev);

    bufferevent_setcb(client.bev, sockread, NULL, sockevent, NULL);

    if(bufferevent_socket_connect_hostname(client.bev, client.dns,
                                           AF_UNSPEC, argv[1], atoi(argv[2])))
    {
        fprintf(stderr, "Failed to start connecting!\n");
    } else {
        client.running = 1;
        event_base_loop(client.base, 0);
        client.running = 0;
    }

    cleanup_session();

    evdns_base_free(client.dns, 1);
    event_base_free(client.base);

    memset(&client, 0, sizeof(client));

    return 0;
}
