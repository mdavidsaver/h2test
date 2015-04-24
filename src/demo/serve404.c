/** @file serve404.c
 *
 * NGHTTP2 based server which returns 404 for all requests
 */
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
#include <event2/buffer.h>
#include <event2/bufferevent.h>
#include <event2/listener.h>

#include <nghttp2/nghttp2.h>

#include "util.h"
#include "h2transport.h"

#define TXBUF (16*1024)

typedef struct {
    struct event_base *base;
    struct evconnlistener *listener;
} server;

typedef struct {
    h2session S; /* must be first */

    server *serv;
    struct event *pingtimer;
} session;

typedef struct {
    h2stream R;

    const char *buf, *alloc;
} request;

static
int stream_have_header(h2stream *strm, const nghttp2_nv *hdr)
{
    printf("Header: %s: %s\n", hdr->name, hdr->value);
    return 0;
}

static const char msg404[] = "No one is home\n";

static
int stream_have_eoh(h2stream *strm)
{
    request *req = CONTAINER(strm, request, R);
    nghttp2_nv hdr404[] = {MAKE_NV(":status", "404"),
                           MAKE_NV("content-encoding", "text/plain")};
    req->buf = req->alloc = malloc(ARRLEN(msg404));
    memcpy((char*)req->buf, msg404, ARRLEN(msg404));
    printf("Send response\n");
    return h2session_respond(strm, hdr404, ARRLEN(hdr404));
}

static
int stream_have_eoi(h2stream *strm)
{
    printf("Request data ends\n");
    return 0;
}

static
void stream_close(h2stream *strm)
{
    request *req = CONTAINER(strm, request, R);
    free((char*)req->alloc);
    memset(req, 0, sizeof(*req));
    free(req);
    printf("Stream ends\n");
}

static
int stream_read(h2stream* S, const char *buf, size_t blen)
{
    printf("Server received %lu '", (unsigned long)blen);
    fprintf_bytes(stdout, buf, blen);
    printf("'\n");
    return 0;
}

static
ssize_t stream_write(h2stream* S, char *buf, size_t blen)
{
    request *req = CONTAINER(S, request, R);
    size_t L = strlen(req->buf);
    if(L>blen)
        L = blen;
    memcpy(buf, req->buf, L);
    req->buf += L;
    printf("Server sent %lu bytes\n", (unsigned long)L);
    return L;
}

static
h2stream* buildstream(h2session* sess)
{
    request *strm = calloc(1, sizeof(*strm));
    if(!strm) return NULL;
    strm->R.have_header = &stream_have_header;
    strm->R.have_eoh = &stream_have_eoh;
    strm->R.have_eoi = &stream_have_eoi;
    strm->R.close = &stream_close;
    strm->R.read = &stream_read;
    strm->R.write = &stream_write;
    return &strm->R;
}

static
int prepare_h2_session(session *sess)
{
    int ret;
    nghttp2_option *option;
    nghttp2_session_callbacks *callbacks;

    if(nghttp2_option_new(&option)==0 &&
       nghttp2_session_callbacks_new(&callbacks)==0)
    {
        h2session_setup_h2(&sess->S, callbacks, option);

        if(nghttp2_session_server_new2(&sess->S.h2sess, callbacks, sess, option)) {
            fprintf(stderr, "Failed to create server session\n");
            ret = 1;

        } else
            ret = 0;

    } else {
        fprintf(stderr, "Failed to alloc options/callbacks\n");
        ret = 1;
    }
    nghttp2_session_callbacks_del(callbacks);
    nghttp2_option_del(option);
    return ret;
}

static
void cleanup_session(h2session *h2sess)
{
    session *sess = CONTAINER(h2sess, session, S);
    nghttp2_session_del(sess->S.h2sess);
    event_free(sess->pingtimer);
    bufferevent_free(sess->S.bev);
    free(sess);
}

static
void pingconn(evutil_socket_t s, short evt, void *raw)
{
    session *sess = raw;

    if(nghttp2_submit_ping(sess->S.h2sess, NGHTTP2_FLAG_NONE, NULL) ||
            nghttp2_session_send(sess->S.h2sess))
    {
        fprintf(stderr, "Ping failed\n");
        cleanup_session(&sess->S);
    }
}

static
void newconn(struct evconnlistener *lev, evutil_socket_t sock, struct sockaddr *cli, int socklen, void *raw)
{
    server *serv = raw;
    session *sess;
    printf("New client\n");
    sess = calloc(1, sizeof(*sess));
    if(sess) {
        sess->serv = serv;
        sess->S.build_stream = buildstream;
        sess->S.cleanup = &cleanup_session;
        /* periodic timer */
        sess->pingtimer = event_new(serv->base, -1, EV_PERSIST, pingconn, sess);
        assert(sess->pingtimer);
        sess->S.bev = bufferevent_socket_new(serv->base, sock, BEV_OPT_CLOSE_ON_FREE);
        if(sess->S.bev) {
            h2session_setup_bev(&sess->S);
            bufferevent_enable(sess->S.bev, EV_READ);

            if(prepare_h2_session(sess)) {
                bufferevent_free(sess->S.bev);
                free(sess);
                printf("Client failed\n");
                return;

            } else {
                nghttp2_settings_entry iv[] = {
                    {NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, 100},
                    {NGHTTP2_SETTINGS_ENABLE_PUSH, 0}
                };
                int rv;

                if ((rv=nghttp2_submit_settings(sess->S.h2sess, NGHTTP2_FLAG_NONE, iv, ARRLEN(iv))) ||
                        (rv=nghttp2_session_send(sess->S.h2sess)))
                {
                    printf("submit error: %s", nghttp2_strerror(rv));
                    cleanup_session(&sess->S);
                } else {
                    const struct timeval itvl = {5,0};
                    printf("Connection ready\n");
                    evtimer_add(sess->pingtimer, &itvl);
                }
            }
        }
    }
    if(!sess || !sess->S.bev) {
        fprintf(stderr, "No memory\n");
        free(sess);
        close(sock);
        return;
    }
}

static
void listenerr(struct evconnlistener *lev, void *raw)
{
    fprintf(stderr, "Listener error?\n");
}

int main(int argc, char *argv[])
{
    void *sighandle;
    struct sockaddr_in addr;
    server serv;

    if(argc<2)
        return 2;

    serv.base = event_base_new();
    assert(serv.base);

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(atoi(argv[1]));

    serv.listener = evconnlistener_new_bind(serv.base, newconn, &serv,
                                            LEV_OPT_CLOSE_ON_FREE | LEV_OPT_REUSEABLE,
                                            4, (struct sockaddr*)&addr, sizeof(addr));
    assert(serv.listener);

    evconnlistener_set_error_cb(serv.listener, listenerr);

    sighandle = setsighandle(serv.base);

    printf("Running\n");
    event_base_loop(serv.base, 0);
    printf("Stopping\n");

    evconnlistener_free(serv.listener);

    cancelsighandle(sighandle);

    event_base_free(serv.base);

    memset(&serv, 0, sizeof(serv));

    printf("Done\n");
    return 0;
}
