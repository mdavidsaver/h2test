#ifndef H2INTERNAL_H
#define H2INTERNAL_H

#include <stdexcept>
#include <set>

#include <event2/event.h>
#include <event2/buffer.h>
#include <event2/bufferevent.h>
#include <event2/listener.h>
#include <nghttp2/nghttp2.h>

#include "h2op.h"

namespace H2 {

struct RawRequest
{
    RawRequest(Transport *s, int32_t id);
    virtual ~RawRequest();

    Transport *sock;
    RequestInfo info;
    Stream *user;
    int32_t streamid;

    bufferevent *sock_bev, *user_bev;
    // tx - user to socket,  write to user_bev, read from sock_bev
    // rx - socket to user, read from user_bev,  write to sock_bev
    bool txpaused, txeoi, rxeoi, sentheaders;

    void set_user(Stream *s)
    {
        user = s;
        s->req = this;
    }

    virtual void handle_pseudo_header(const std::string& name, const std::string& value) {}
    virtual void end_of_headers()=0;
    virtual void end_of_data()=0;
};

struct Transport
{
    Transport(event_base *base);
    virtual ~Transport();

    void setup_bev();
    void start_bev();

    void setup_ng2(nghttp2_session_callbacks *callbacks,
                   nghttp2_option *option);

    event_base *base;
    std::set<RawRequest*> active_requests;

    sockaddr_pun peer;
    std::string myname;
    struct bufferevent *bev;
    nghttp2_session *h2sess;

    event *deferedsend;

    bool sendwait;
    bool incb;
    bool queuesend;

    void queue_deferred_send();
    void send_now();

    struct InCallback {
        Transport *T;
        InCallback(Transport *T) :T(T) {T->incb=true;}
        ~InCallback() {T->incb = false;}
    };

    virtual void connect() {}

    virtual void destory()=0; // delete this; happens here
    // nghttp2 callbacks

    // nghttp2_data_provider::read_callback
    static ssize_t stream_write(
            nghttp2_session *session, int32_t stream_id, uint8_t *buf, size_t length,
            uint32_t *data_flags, nghttp2_data_source *source, void *user_data);
};

struct ServerTransport : public Transport
{
    ServerTransport(Server *, event_base *, evutil_socket_t sock, const sockaddr_pun &);
    virtual ~ServerTransport();

    Server *server;
    event *pingtimer;

    virtual void destory();
};

} // namespace H2

#endif // H2INTERNAL_H
