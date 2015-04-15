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

#define TXBUF (16*1024)

typedef struct {
    struct event_base *base;
    struct evconnlistener *listener;
} server;

typedef struct request request;

typedef struct {
    server *serv;
    struct bufferevent *bev;
    struct event *pingtimer;
    nghttp2_session *h2sess;

    unsigned int sendwait:1;

    request *first;
} session;

struct request {
    session *sess;
    request *next;

    int32_t streamid;
};

/* on_begin_headers_callback, start of a new stream (request) */
static
int request_begin(nghttp2_session *h2sess,
                  const nghttp2_frame *frame,
                  void *raw)
{
    session *sess = raw;
    request *req = calloc(1, sizeof(*req));
    assert(sess->h2sess==h2sess);

    if(!req) {
        fprintf(stderr, "Failed to alloc request\n");
        return NGHTTP2_ERR_CALLBACK_FAILURE;
    }

    req->sess = sess;
    req->streamid = frame->hd.stream_id;
    printf("Open stream %d\n", (int)req->streamid);

    if(nghttp2_session_set_stream_user_data(h2sess, req->streamid, req)) {
        fprintf(stderr, "Failed to add request\n");
        free(req);
        return nghttp2_submit_rst_stream(h2sess, NGHTTP2_FLAG_NONE,
                                         frame->hd.stream_id, NGHTTP2_ERR_INVALID_ARGUMENT);
    }

    req->next = sess->first;
    sess->first = req;
    return 0;
}

static
int request_end(nghttp2_session *h2sess, int32_t streamid,
                uint32_t error_code, void *raw)
{
    session *sess = raw;
    request *req = nghttp2_session_get_stream_user_data(h2sess, streamid);

    if(!req) {
        printf("Close unknown stream\n");
        return 0;
    }

    printf("Close stream %d = %u\n", (int)req->streamid, error_code);

    /* remove from list */
    assert(sess->first);
    if(sess->first==req) {
        sess->first = req->next;

    } else {
        request *prev = sess->first;
        while(1) {
            assert(prev); /* req must be in the list */
            if(prev->next!=req)
                continue;
            prev->next = req->next;
            break;
        }
    }
    free(req);

    return 0;
}

static
int on_frame_recv_callback(nghttp2_session *h2sess,
                                  const nghttp2_frame *frame, void *raw)
{
    session *sess = raw;
    assert(sess->h2sess==h2sess);
    switch(frame->hd.type) {
    case NGHTTP2_HEADERS:
        if(frame->hd.flags & NGHTTP2_FLAG_END_HEADERS)
        {
            /* end of headers */
            int ret;
            request *req = nghttp2_session_get_stream_user_data(h2sess, frame->hd.stream_id);
            nghttp2_nv hdr404[] = {MAKE_NV(":status", "404")};

            if(req) {

                assert(req->streamid==frame->hd.stream_id);

                /* process request */
                ret = nghttp2_submit_response(h2sess, req->streamid, hdr404, ARRLEN(hdr404), NULL);
                if(ret) {
                    fprintf(stderr, "Failed to submit response: %d\n", ret);
                    return nghttp2_submit_rst_stream(h2sess, NGHTTP2_FLAG_NONE,
                                                     frame->hd.stream_id, ret);
                }
            }

        }
        break;
    case NGHTTP2_PING:
        if(frame->hd.flags & NGHTTP2_FLAG_ACK)
        {
            /* PING ack. */
            printf("pong\n");
        }
        break;
    case NGHTTP2_GOAWAY:
        break;
    default:
        break;
    }

    return 0;
}

/* move data from nghttp2's send queue into bufferevent's TX queue */
static
ssize_t send_sess_data(nghttp2_session *h2sess,
                       const uint8_t *data, size_t length,
                       int flags, void *raw)
{
    session *sess = raw;
    struct evbuffer *buf = bufferevent_get_output(sess->bev);

    assert(sess->h2sess==h2sess);

    if(sess->sendwait)
        return NGHTTP2_ERR_WOULDBLOCK;

    if(evbuffer_add(buf, data, length)) {
        fprintf(stderr, "send_sess_data error\n");
        return NGHTTP2_ERR_CALLBACK_FAILURE;
    }

    if(evbuffer_get_length(buf)>=TXBUF) {
        /* TX buffer is (more than) full, so enable write callback
         * when buffer length is < TXBUF (aka. EV_WRITE low water-mark)
         */
        printf("Throttle\n");
        sess->sendwait = 1;
        bufferevent_enable(sess->bev, EV_WRITE);
    }

    printf("Tx %lu '", (unsigned long)length);
    fprintf_bytes(stdout, data, length);
    printf("'\n");
    return length;
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
        nghttp2_option_set_recv_client_preface(option, 1);

        nghttp2_session_callbacks_set_send_callback(callbacks, send_sess_data);

        nghttp2_session_callbacks_set_on_frame_recv_callback(callbacks, on_frame_recv_callback);
        nghttp2_session_callbacks_set_on_begin_headers_callback(callbacks, request_begin);
        nghttp2_session_callbacks_set_on_stream_close_callback(callbacks, request_end);

        if(nghttp2_session_server_new2(&sess->h2sess, callbacks, sess, option)) {
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
void cleanup_session(session *sess)
{
    nghttp2_session_del(sess->h2sess);
    event_free(sess->pingtimer);
    bufferevent_free(sess->bev);
    assert(sess->first==NULL);
    free(sess);
}

/* Move data from bufferevent's RX queue to the NGHTTP2 sesssions input queue */
static
void sockread(struct bufferevent *bev, void *raw)
{
    session *sess = raw;
    struct evbuffer *buf = bufferevent_get_input(bev);
    size_t blen = evbuffer_get_length(buf);
    unsigned char *cbuf = evbuffer_pullup(buf, -1);
    ssize_t ret;

    if(!cbuf) {
        fprintf(stderr, "buf too long! %lu\n", (unsigned long)blen);
        return;
    }

    ret = nghttp2_session_mem_recv(sess->h2sess, cbuf, blen);
    printf("Rx %lu '", (unsigned long)blen);
    fprintf_bytes(stdout, cbuf, blen);
    printf("'\n");
    evbuffer_drain(buf, blen);

    if(ret<0) {
        fprintf(stderr, "recv error %s\n", nghttp2_strerror(ret));
        cleanup_session(sess);
        return;

    } else if(!sess->sendwait) {
        if(nghttp2_session_send(sess->h2sess)) {
            fprintf(stderr, "send after recv error\n");
            cleanup_session(sess);
        }
    }
}

static
void sockwrite(struct bufferevent *bev, void *raw)
{
    int ret;
    session *sess = raw;
    if(!sess->sendwait) return;
    sess->sendwait = 0;

    ret = nghttp2_session_send(sess->h2sess);
    if(ret) {
        fprintf(stderr, "send error:%s \n", nghttp2_strerror(ret));
        cleanup_session(sess);

    } else if(sess->sendwait==0) {
        /* didn't fill the TX buffer, so disable write callback */
        bufferevent_disable(sess->bev, EV_WRITE);
        printf("Un-Throttle\n");
    }
}

static
void sockevent(struct bufferevent *bev, short what, void *raw)
{
    session *sess = raw;
    if(what&BEV_EVENT_CONNECTED) {
        printf("?????????????? already connected ????????\n");

    } else {
        if(what&BEV_EVENT_ERROR) {
            printf("Client error\n");
        }
        if(what&BEV_EVENT_TIMEOUT) {
            printf("Client timeout\n");
        }
        printf("Client close\n");
        cleanup_session(sess);
    }
}

static
void pingconn(evutil_socket_t s, short evt, void *raw)
{
    session *sess = raw;

    if(nghttp2_submit_ping(sess->h2sess, NGHTTP2_FLAG_NONE, NULL) ||
            nghttp2_session_send(sess->h2sess))
    {
        fprintf(stderr, "Ping failed\n");
        cleanup_session(sess);
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
        /* periodic timer */
        sess->pingtimer = event_new(serv->base, -1, EV_PERSIST, pingconn, sess);
        assert(sess->pingtimer);
        sess->bev = bufferevent_socket_new(serv->base, sock, BEV_OPT_CLOSE_ON_FREE);
        if(sess->bev) {
            const struct timeval txtmo = {10,0}, rxtmo = {10,0};

            bufferevent_setcb(sess->bev, sockread, sockwrite, sockevent, sess);
            bufferevent_setwatermark(sess->bev, EV_READ, 0, 1024);
            bufferevent_setwatermark(sess->bev, EV_WRITE, TXBUF, 0);
            bufferevent_set_timeouts(sess->bev, &rxtmo, &txtmo);
            bufferevent_enable(sess->bev, EV_READ);

            if(prepare_h2_session(sess)) {
                bufferevent_free(sess->bev);
                free(sess);
                printf("Client failed\n");
                return;

            } else {
                nghttp2_settings_entry iv[] = {
                    {NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, 100},
                    {NGHTTP2_SETTINGS_ENABLE_PUSH, 0}
                };
                int rv;

//                bufferevent_write(sess->bev, NGHTTP2_CLIENT_CONNECTION_PREFACE,
//                                NGHTTP2_CLIENT_CONNECTION_PREFACE_LEN);

                if ((rv=nghttp2_submit_settings(sess->h2sess, NGHTTP2_FLAG_NONE, iv, ARRLEN(iv))) ||
                        (rv=nghttp2_session_send(sess->h2sess)))
                {
                    printf("submit error: %s", nghttp2_strerror(rv));
                    cleanup_session(sess);
                } else {
                    const struct timeval itvl = {5,0};
                    printf("Connection ready\n");
                    evtimer_add(sess->pingtimer, &itvl);
                }
            }
        }
    }
    if(!sess || !sess->bev) {
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
