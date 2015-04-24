#ifndef H2INTERNAL_H
#define H2INTERNAL_H

#include <ostream>
#include <stdexcept>

#include <event2/event.h>
#include <event2/buffer.h>
#include <event2/bufferevent.h>
#include <event2/listener.h>
#include <nghttp2/nghttp2.h>

#include "h2op.h"

namespace H2 {

union sockaddr_pun {
    sockaddr_in in;
    sockaddr_in6 in6;
};

struct RawRequest
{
    Transport *sock;
    RequestInfo info;
    Request *user;
    int32_t streamid;
};

struct Transport
{
    Transport();
    ~Transport();

    void setup_bev();
    void start_bev();

    void setup_ng2(nghttp2_session_callbacks *callbacks,
                   nghttp2_option *option);

    std::string myname;
    struct bufferevent *bev;
    nghttp2_session *h2sess;

    bool sendwait;

    virtual void connect() {}

    virtual void destory();
    // nghttp2 callbacks

    // on_begin_headers_callback()
    static int stream_begin(nghttp2_session *h2sess,
                            const nghttp2_frame *frame,
                            void *raw);
    // nghttp2_session_callbacks_set_on_stream_close_callback()
    static int stream_end(nghttp2_session *h2sess, int32_t streamid,
                          uint32_t error_code, void *raw);
    // nghttp2_session_callbacks_set_on_header_callback()
    static int stream_header(nghttp2_session *session,
                             const nghttp2_frame *frame, const uint8_t *name,
                             size_t namelen, const uint8_t *value,
                             size_t valuelen, uint8_t flags,
                             void *user_data);
    // nghttp2_session_callbacks_set_on_frame_recv_callback()
    static int on_frame_recv_callback(nghttp2_session *h2sess,
                                      const nghttp2_frame *frame, void *raw);
    // nghttp2_session_callbacks_set_on_data_chunk_recv_callback()
    static int stream_read(nghttp2_session *session,
                           uint8_t flags,
                           int32_t stream_id,
                           const uint8_t *data,
                           size_t len, void *user_data);
    // nghttp2_data_provider::read_callback
    static ssize_t stream_write(
            nghttp2_session *session, int32_t stream_id, uint8_t *buf, size_t length,
            uint32_t *data_flags, nghttp2_data_source *source, void *user_data);
};

struct ServerTransport : public Transport
{
    ServerTransport(Server *, event_base *, evutil_socket_t sock, const sockaddr_pun &);
    ~ServerTransport();

    Server *server;
    event *pingtimer;
};

} // namespace H2

std::ostream& operator<<(std::ostream& strm, H2::sockaddr_pun addr);

#endif // H2INTERNAL_H
