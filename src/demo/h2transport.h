#ifndef H2TRANSPORT_H
#define H2TRANSPORT_H
/** @file h2transport.h
 *
 * Interface between a bufferevent and an nghttp2_session
 * common to client and server
 */

#include <nghttp2/nghttp2.h>
#include <event2/bufferevent.h>

typedef struct h2session h2session;
typedef struct h2stream h2stream;

struct h2session {
    struct bufferevent *bev;
    nghttp2_session *h2sess;
    unsigned int sendwait:1;
    unsigned int autoacksess:1;

    void (*cleanup)(h2session*);
    int (*connect)(h2session*);
    h2stream* (*build_stream)(h2session*);

    h2stream *strm_first;
};

struct h2stream {
    h2session *sess;
    h2stream *strm_next, *strm_prev;

    int32_t streamid;

    unsigned int sendwait:1;

    int (*have_header)(h2stream*, const nghttp2_nv*);
    int (*have_eoh)(h2stream*);
    int (*have_eoi)(h2stream*);
    void (*close)(h2stream*);

    int (*read)(h2stream* S, const char *buf, size_t blen);
    ssize_t (*write)(h2stream* S, char *buf, size_t blen);
};

int h2session_setup_bev(h2session *sess);
int h2session_setup_h2(h2session *sess,
                       nghttp2_session_callbacks *callbacks,
                       nghttp2_option *options);

h2stream* h2session_request(h2session *sess, nghttp2_nv *hdrs, size_t nhdrs);
int h2session_respond(h2stream *strm, nghttp2_nv *hdrs, size_t nhdrs);

int h2stream_can_write(h2stream* strm);

#endif /* H2TRANSPORT_H */
