
#include <stdlib.h>
#include <assert.h>
#include <string.h>

#include <event2/event.h>
#include <event2/buffer.h>

#include "h2transport.h"
#include "util.h"

#define RXBUF 1024
#define TXBUF (16*1024)

static
void cleanup_session(h2session *sess)
{
    h2stream *strm = sess->strm_first, *nextstrm = NULL;
    while(strm)
    {
        if(strm->strm_next)
            nextstrm = strm->strm_next;

        (*strm->close)(strm);

        strm = nextstrm;
        nextstrm = NULL;
    }
    if(sess->cleanup)
        (*sess->cleanup)(sess);
}
/* on_begin_headers_callback, start of a new stream (request) */
static
int stream_begin(nghttp2_session *h2sess,
                 const nghttp2_frame *frame,
                 void *raw)
{
    uint32_t err = 0;
    h2session *sess = raw;
    h2stream *strm;

    assert(sess->h2sess==h2sess);

    strm = nghttp2_session_get_stream_user_data(h2sess, frame->hd.stream_id);
    if(!strm && sess->build_stream && (strm = (*sess->build_stream)(sess))!=NULL)
    {
        if(nghttp2_session_set_stream_user_data(h2sess, frame->hd.stream_id, strm)) {
            (*strm->close)(strm);
            strm = NULL;
        } else {
            strm->sess = sess;
            strm->streamid = frame->hd.stream_id;

            strm->strm_prev = NULL;
            strm->strm_next = sess->strm_first;
            sess->strm_first = strm;
        }
    }

    if(!err && !strm) err = NGHTTP2_ERR_INVALID_ARGUMENT;

    if(err)
        return nghttp2_submit_rst_stream(h2sess, NGHTTP2_FLAG_NONE,
                                         frame->hd.stream_id, err);
    else
        return 0;
}

static
int stream_header(nghttp2_session *session,
                  const nghttp2_frame *frame, const uint8_t *name,
                  size_t namelen, const uint8_t *value,
                  size_t valuelen, uint8_t flags,
                  void *user_data)
{
    int err;
    nghttp2_nv hdr;
    h2session *sess = user_data;
    h2stream *strm = nghttp2_session_get_stream_user_data(session, frame->hd.stream_id);
    if(!strm) return 0;

    assert(strm->sess==sess);
    assert(strm->sess->h2sess==session);
    assert(strm->streamid==frame->hd.stream_id);

    hdr.name = (uint8_t*)name;
    hdr.namelen = namelen;
    hdr.value = (uint8_t*)value;
    hdr.valuelen = valuelen;
    hdr.flags = flags;

    if(!strm->have_header)
        return 0;
    err = (*strm->have_header)(strm, &hdr);
    if(err)
        return nghttp2_submit_rst_stream(session, NGHTTP2_FLAG_NONE,
                                         frame->hd.stream_id, err);
    else
        return 0;
}

static
int stream_end(nghttp2_session *h2sess, int32_t streamid,
               uint32_t error_code, void *raw)
{
    h2session *sess = raw;
    h2stream *strm;

    assert(sess->h2sess==h2sess);

    strm = nghttp2_session_get_stream_user_data(h2sess, streamid);
    if(!strm) return 0;

    if(strm->strm_prev)
        strm->strm_prev->strm_next = strm->strm_next;
    if(strm->strm_next)
        strm->strm_next->strm_prev = strm->strm_prev;
    if(sess->strm_first==strm)
        sess->strm_first = strm->strm_next;

    (*strm->close)(strm);
    return 0;
}

static
int on_frame_recv_callback(nghttp2_session *h2sess,
                                  const nghttp2_frame *frame, void *raw)
{
    h2stream *strm = NULL;
    h2session *sess = raw;

    assert(sess->h2sess==h2sess);

    switch(frame->hd.type) {
    case NGHTTP2_HEADERS:
        if(frame->hd.flags & NGHTTP2_FLAG_END_HEADERS)
        {
            if(!strm) strm = nghttp2_session_get_stream_user_data(h2sess, frame->hd.stream_id);

            if(strm) {
                int ret;
                assert(strm->streamid==frame->hd.stream_id);
                ret = (*strm->have_eoh)(strm);
                if(ret)
                    return nghttp2_submit_rst_stream(h2sess, NGHTTP2_FLAG_NONE,
                                                     frame->hd.stream_id, ret);
            }

        }
        /* no break */
    case NGHTTP2_DATA:

        if(frame->hd.flags & NGHTTP2_FLAG_END_STREAM)
        {
            if(!strm) strm = nghttp2_session_get_stream_user_data(h2sess, frame->hd.stream_id);

            if(strm) {
                int ret;
                assert(strm->streamid==frame->hd.stream_id);
                ret = (*strm->have_eoi)(strm);
                if(ret)
                    return nghttp2_submit_rst_stream(h2sess, NGHTTP2_FLAG_NONE,
                                                     frame->hd.stream_id, ret);
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
    case NGHTTP2_RST_STREAM:
        fprintf(stderr, "Stream %d reset %d\n", frame->hd.stream_id,
                frame->rst_stream.error_code);
        break;
    case NGHTTP2_GOAWAY:
    {
        char *buf = malloc(frame->goaway.opaque_data_len+1);
        if(buf) {
            memcpy(buf, frame->goaway.opaque_data, frame->goaway.opaque_data_len);
            buf[frame->goaway.opaque_data_len] = '\0';
        }
        fprintf(stderr, "Go away: last=%d error=%d: %s\n", frame->goaway.last_stream_id,
                frame->goaway.error_code, buf);
        free(buf);
    }
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
    h2session *sess = raw;
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
int stream_read(nghttp2_session *session,
                uint8_t flags,
                int32_t stream_id,
                const uint8_t *data,
                size_t len, void *user_data)
{
    h2session *sess = user_data;
    h2stream *strm = nghttp2_session_get_stream_user_data(session, stream_id);
    if(!strm) return 0;

    assert(strm->sess==sess);
    assert(strm->sess->h2sess==session);
    assert(strm->streamid==stream_id);

    if(!strm->read)
        return len; /* ignore */

    /* TODO: disable auto ack. */

    return (*strm->read)(strm, (const char*)data, len);
    /* TODO: reset stream on error */
}

/* Move data from bufferevent's RX queue to the NGHTTP2 sesssions input queue */
static
void sockread(struct bufferevent *bev, void *raw)
{
    h2session *sess = raw;
    struct evbuffer *buf = bufferevent_get_input(bev);
    size_t blen = evbuffer_get_length(buf);
    unsigned char *cbuf = evbuffer_pullup(buf, -1);
    ssize_t ret;

    if(!cbuf) {
        fprintf(stderr, "buf too long! %lu\n", (unsigned long)blen);
        return;
    }

    printf("Rx buf %lu '", (unsigned long)blen);
    fprintf_bytes(stdout, cbuf, blen);
    printf("'\n");
    ret = nghttp2_session_mem_recv(sess->h2sess, cbuf, blen);

    if(ret<=0) {
        fprintf(stderr, "recv error %s\n", nghttp2_strerror(ret));
        cleanup_session(sess);
        return;

    } else if(!sess->sendwait) {
        if(nghttp2_session_send(sess->h2sess)) {
            fprintf(stderr, "send after recv error\n");
            cleanup_session(sess);
        }
    }
    printf("Rx consume %ld \n", (long)ret);
    evbuffer_drain(buf, ret);
}

static
void sockwrite(struct bufferevent *bev, void *raw)
{
    int ret;
    h2session *sess = raw;
    if(!sess->sendwait) return;
    sess->sendwait = 0;

    ret = nghttp2_session_send(sess->h2sess);
    if(ret) {
        fprintf(stderr, "send error:%s \n", nghttp2_strerror(ret));
        cleanup_session(sess);

    } else if(sess->sendwait==0) {
        /* didn't (re)fill the TX buffer, so disable write callback */
        bufferevent_disable(sess->bev, EV_WRITE);
        printf("Un-Throttle\n");
    }
}

static
void sockevent(struct bufferevent *bev, short what, void *raw)
{
    h2session *sess = raw;
    if(what&BEV_EVENT_CONNECTED) {
        assert(sess->h2sess==NULL);
        /* client only */
        if(sess->connect && (*sess->connect)(sess))
            return; /* connect() is expected to cleanup and free sess on error */

    } else {
        if(what&BEV_EVENT_ERROR) {
            printf("Socket error\n");
        }
        if(what&BEV_EVENT_TIMEOUT) {
            printf("Socket timeout\n");
        }
        printf("Socket close\n");
        cleanup_session(sess);
    }
}

int h2session_setup_bev(h2session *sess)
{
    const struct timeval txtmo = {10,0}, rxtmo = {10,0};

    bufferevent_setcb(sess->bev, sockread, sockwrite, sockevent, sess);
    bufferevent_setwatermark(sess->bev, EV_READ, 0, RXBUF);
    bufferevent_setwatermark(sess->bev, EV_WRITE, TXBUF, 0);
    bufferevent_set_timeouts(sess->bev, &rxtmo, &txtmo);
    return 0;
}

int h2session_setup_h2(h2session *sess,
                       nghttp2_session_callbacks *callbacks,
                       nghttp2_option *option)
{
    nghttp2_option_set_recv_client_preface(option, 1);
    nghttp2_session_callbacks_set_send_callback(callbacks, send_sess_data);
    nghttp2_session_callbacks_set_on_begin_headers_callback(callbacks, stream_begin);
    nghttp2_session_callbacks_set_on_header_callback(callbacks, stream_header);
    nghttp2_session_callbacks_set_on_stream_close_callback(callbacks, stream_end);
    nghttp2_session_callbacks_set_on_frame_recv_callback(callbacks, on_frame_recv_callback);
    nghttp2_session_callbacks_set_on_data_chunk_recv_callback(callbacks, stream_read);
    return 0;
}

static
ssize_t stream_write(
        nghttp2_session *session, int32_t stream_id, uint8_t *buf, size_t length,
        uint32_t *data_flags, nghttp2_data_source *source, void *user_data)
{
    ssize_t ret;
    h2session *sess = user_data;
    h2stream *strm = source->ptr;

    assert(strm->sess==sess);
    assert(strm->sess->h2sess==session);
    assert(strm->streamid==stream_id);

    if(!strm->write) {
        *data_flags = NGHTTP2_DATA_FLAG_EOF;
        return 0;
    } else if(strm->sendwait)
        return NGHTTP2_ERR_DEFERRED;

    ret = (*strm->write)(strm, (char*)buf, length);
    if(ret>0) {
        return ret;
    } else if(ret==NGHTTP2_ERR_DEFERRED) {
        strm->sendwait = 1;
        return NGHTTP2_ERR_DEFERRED;
    } else if(ret==0) {
        *data_flags = NGHTTP2_DATA_FLAG_EOF;
        return 0;
    } else
        return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
}

h2stream* h2session_request(h2session *sess, nghttp2_nv *hdrs, size_t nhdrs)
{
    h2stream *strm;
    nghttp2_data_provider prov, *pprov = &prov;
    int32_t streamid;

    strm = (*sess->build_stream)(sess);
    if(!strm) return NULL;

    prov.read_callback = &stream_write;
    prov.source.ptr = strm;
    if(!strm->write)
        pprov = NULL;

    streamid = nghttp2_submit_request(sess->h2sess, NULL, hdrs, nhdrs, pprov, strm);
    if(streamid<=0) {
        fprintf(stderr, "Failed to submit request %d\n", streamid);
        nghttp2_session_set_stream_user_data(strm->sess->h2sess, strm->streamid, NULL);
        (*strm->close)(strm);
        return NULL;
    }

    strm->sess = sess;
    strm->streamid = streamid;

    strm->strm_prev = NULL;
    strm->strm_next = sess->strm_first;
    sess->strm_first = strm;

    return strm;
}

int h2session_respond(h2stream *strm, nghttp2_nv *hdrs, size_t nhdrs)
{
    nghttp2_data_provider prov, *pprov = &prov;
    int32_t err;

    prov.read_callback = &stream_write;
    prov.source.ptr = strm;
    if(!strm->write)
        pprov = NULL;

    err = nghttp2_submit_response(strm->sess->h2sess, strm->streamid, hdrs, nhdrs, pprov);
    if(err) {
        fprintf(stderr, "Failed to submit response %d\n", err);
        nghttp2_session_set_stream_user_data(strm->sess->h2sess, strm->streamid, NULL);
        (*strm->close)(strm);
        return 1;
    }

    return 0;
}


int h2stream_can_write(h2stream* strm)
{
    if(!strm->sendwait) return 0;
    return nghttp2_session_resume_data(strm->sess->h2sess, strm->streamid);
}
