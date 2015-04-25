
#include <assert.h>

#include "h2internal.h"

static
void request_ack(struct evbuffer *buffer, const struct evbuffer_cb_info *info, void *arg)
{
    H2::RawRequest *self = (H2::RawRequest*)arg;
    if(info->n_deleted) {
        printf("%s: stream %u %p comsumes %lu bytes\n", self->sock->myname.c_str(),
               self->streamid, self, (unsigned long)info->n_deleted);
        int err = nghttp2_session_consume_stream(self->sock->h2sess, self->streamid, info->n_deleted);
        if(err)
            fprintf(stderr, "%s: Failed to consume stream %d\n", self->sock->myname.c_str(), self->streamid);
        else
            self->sock->queue_deferred_send();
    }
}

static
void stream_events(struct bufferevent *bev, short what, void *raw)
{
    H2::RawRequest *self = (H2::RawRequest*)raw;
    assert(bev==self->sock_bev);
    if(what&(BEV_EVENT_EOF))
    {
        if(what&BEV_EVENT_READING) { // end of user to sock
            self->txeoi = true;
            bufferevent_disable(bev, EV_READ);
        }
        if(what&BEV_EVENT_WRITING) { // end of sock to user
            self->rxeoi = true;
        }
    }
}

static
void stream_user_to_sock(struct bufferevent *bev, void *raw)
{
    H2::RawRequest *self = (H2::RawRequest*)raw;
    assert(bev==self->sock_bev);

    // writing data to stream
    if(self->txpaused) {
        if(nghttp2_session_resume_data(self->sock->h2sess, self->streamid))
            fprintf(stderr, "%s: error resuming stream\n", self->sock->myname.c_str());
        else
            self->sock->queue_deferred_send();
    }
}

namespace H2 {

RawRequest::RawRequest(Transport *s, int32_t id)
    :sock(s)
    ,user(0)
    ,streamid(id)
    ,sock_bev(NULL)
    ,user_bev(NULL)
    ,txpaused(false)
    ,txeoi(false)
    ,rxeoi(false)
    ,sentheaders(false)
{
    bufferevent *pair[2] = {NULL, NULL};
    if(bufferevent_pair_new(s->base, BEV_OPT_DEFER_CALLBACKS, pair))
        throw std::bad_alloc();
    try{
        sock_bev = pair[0];
        user_bev = pair[1];

        // hook into user's receive buffer
        // to acknowledge as data is removed
        evbuffer *touser = bufferevent_get_output(sock_bev);
        if(!evbuffer_add_cb(touser, request_ack, this))
            throw std::runtime_error("Failed to add buf cb");

        bufferevent_setcb(sock_bev, stream_user_to_sock, NULL, stream_events, this);
        bufferevent_setwatermark(sock_bev, EV_READ, 0, 32768);
        // READ|WRITE not enabled until headers received

    }catch(...){
        bufferevent_free(pair[0]);
        bufferevent_free(pair[1]);
        throw;
    }
}

RawRequest::~RawRequest()
{
    if(sock_bev) bufferevent_free(sock_bev);
    if(user_bev) bufferevent_free(user_bev);
    delete user;
}

} // namespace H2
