
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <assert.h>

#include "h2internal.h"

#define ARRLEN(x) (sizeof(x) / sizeof(x[0]))

/* socket read bufferevent bound */
#define RXBUF (2*NGHTTP2_INITIAL_WINDOW_SIZE)
/* socket write bufferevent bound */
#define TXBUF (2*NGHTTP2_INITIAL_WINDOW_SIZE)

static
void bev_event(struct bufferevent *bev, short what, void *raw)
{
    H2::Transport *sock = (H2::Transport*)raw;
    if(what&BEV_EVENT_CONNECTED) {
        try{
            if(sock->h2sess!=NULL)
                throw std::logic_error("Transport already has H2 session");
            sock->connect();
            if(sock->h2sess==NULL)
                throw std::logic_error("connect failed to setup H2 session");
            return;
        }catch(std::exception& e){
            fprintf(stderr, "%s: exception in Transport::connect: %s",
                    sock->myname.c_str(), e.what());
        }

    } else {
        if(what&BEV_EVENT_ERROR) {
            int err = EVUTIL_SOCKET_ERROR();
            const char *msg = evutil_socket_error_to_string(err);
            fprintf(stderr, "%s: Socket error: %s\n",
                    sock->myname.c_str(), msg);
        }
        if(what&BEV_EVENT_TIMEOUT) {
            fprintf(stderr, "%s: Socket timeout\n",
                    sock->myname.c_str());
        }
    }
    printf("%s: Socket closes\n",
           sock->myname.c_str());
    sock->destory();
}

static
void bev_read(struct bufferevent *bev, void *raw)
{
    H2::Transport *sock = (H2::Transport*)raw;
    struct evbuffer *buf = bufferevent_get_input(bev);
    int h2error = 0;

    evbuffer_iovec vect[4];
    int N = evbuffer_peek(buf, -1, NULL, vect, ARRLEN(vect));
    if(N<0)
        return;
    if((size_t)N>ARRLEN(vect))
        N = ARRLEN(vect);

    try{

        size_t consumed = 0;
        for(int i=0; i<N; i++) {
            ssize_t ret = nghttp2_session_mem_recv(sock->h2sess, (uint8_t*)vect[i].iov_base, vect[i].iov_len);
            if(ret<0) {
                h2error = ret;
                throw std::runtime_error("Error during receive");
            }
            consumed += ret;
            if((size_t)ret<vect[i].iov_len)
                break; /* didn't consume entire chunk, so break and try again later */
        }
        if(consumed==0)
            fprintf(stderr, "%s: Warning, RX consumed zero bytes\n", sock->myname.c_str());
        evbuffer_drain(buf, consumed);

        if(!sock->sendwait && (h2error=nghttp2_session_send(sock->h2sess)))
            throw std::runtime_error("Error during send");

        printf("%s Rx consume %ld %d/%d\n", sock->myname.c_str(), (long)consumed,
               nghttp2_session_get_effective_recv_data_length(sock->h2sess),
               nghttp2_session_get_effective_local_window_size(sock->h2sess));
    }catch(std::exception& e){
        fprintf(stderr, "%s: Error %d in bev_read: %s",
                sock->myname.c_str(), h2error, e.what());
        sock->destory();
    }
}

static
ssize_t send_sess_data(nghttp2_session *h2sess,
                       const uint8_t *data, size_t length,
                       int flags, void *raw)
{
    H2::Transport *self = (H2::Transport*)raw;
    struct evbuffer *buf = bufferevent_get_output(self->bev);
    assert(self->h2sess==h2sess);

    if(self->sendwait)
        return NGHTTP2_ERR_WOULDBLOCK;

    if(evbuffer_add(buf, data, length)) {
        fprintf(stderr, "%s: send_sess_data add data failed\n",
                self->myname.c_str());
        return NGHTTP2_ERR_CALLBACK_FAILURE;
    } else if(evbuffer_get_length(buf)>=TXBUF) {
        /* TX buffer is (more than) full, so enable write callback
         * when buffer length is < TXBUF (aka. EV_WRITE low water-mark)
         */
        self->sendwait = 1;
        bufferevent_enable(self->bev, EV_WRITE);
    }
    return length;
}

static
void bev_write(struct bufferevent *bev, void *raw)
{
    H2::Transport *sock = (H2::Transport*)raw;

    if(!sock->sendwait) return;
    sock->sendwait = 0;

    int ret = nghttp2_session_send(sock->h2sess);
    if(ret) {
        fprintf(stderr, "%s: Error %d in bev_write",
                sock->myname.c_str(),ret);
        sock->destory();

    } else if(sock->sendwait==0) {
        /* didn't (re)fill the TX buffer, so disable write callback */
        bufferevent_disable(sock->bev, EV_WRITE);
    }
}

static
int stream_header(nghttp2_session *session,
                  const nghttp2_frame *frame, const uint8_t *name,
                  size_t namelen, const uint8_t *value,
                  size_t valuelen, uint8_t flags,
                  void *raw)
{
    if(namelen==0) return 0;

    H2::Transport *sock = (H2::Transport*)raw;
    H2::RawRequest *req = (H2::RawRequest*)nghttp2_session_get_stream_user_data(session, frame->hd.stream_id);
    if(!req) return 0;

    assert(sock->h2sess==session);
    assert(req->sock==sock);
    assert(req->streamid==frame->hd.stream_id);

    std::string hname((const char*)name, namelen);

    H2::RequestInfo::headers_t::iterator it = req->info.headers.find(hname);
}

namespace H2 {

Transport::Transport()
    :bev(0), h2sess(0), sendwait(false)
{}

Transport::~Transport()
{
    nghttp2_session_del(h2sess);
    if(bev) bufferevent_free(bev);
}

void Transport::setup_bev()
{
    const struct timeval txtmo = {20,0}, rxtmo = {20,0};

    bufferevent_setcb(bev, bev_read, bev_write, bev_event, this);
    /* buffer up to RXBUF bytes of input */
    bufferevent_setwatermark(bev, EV_READ, 0, RXBUF);
    /* when Tx buffer is full, wait until it is half empty
     * before adding more
     */
    bufferevent_setwatermark(bev, EV_WRITE, TXBUF/2, 0);
    bufferevent_set_timeouts(bev, &rxtmo, &txtmo);
}

void Transport::start_bev()
{
    if(bufferevent_enable(bev, EV_READ))
        throw std::runtime_error("Failed to enable buffer event");
}

void Transport::setup_ng2(nghttp2_session_callbacks *callbacks, nghttp2_option *option)
{
    nghttp2_option_set_recv_client_preface(option, 1);
    nghttp2_option_set_no_auto_window_update(option, 1);

    nghttp2_session_callbacks_set_send_callback(callbacks, send_sess_data);
    nghttp2_session_callbacks_set_on_begin_headers_callback(callbacks, stream_begin);
    nghttp2_session_callbacks_set_on_header_callback(callbacks, stream_header);
    nghttp2_session_callbacks_set_on_stream_close_callback(callbacks, stream_end);
    nghttp2_session_callbacks_set_on_frame_recv_callback(callbacks, on_frame_recv_callback);
    nghttp2_session_callbacks_set_on_data_chunk_recv_callback(callbacks, stream_read);
}

} // namespace H2


std::ostream& operator<<(std::ostream& strm, H2::sockaddr_pun addr)
{
    char buf[30];
    unsigned short port;
    switch(addr.in.sin_family) {
    case AF_INET:
        port = addr.in.sin_port;
        evutil_inet_ntop(AF_INET,  &addr.in.sin_addr, buf, ARRLEN(buf));
        break;
    case AF_INET6:
        port = addr.in6.sin6_port;
        evutil_inet_ntop(AF_INET6, &addr.in6.sin6_addr, buf, ARRLEN(buf));
        break;
    default:
        throw std::runtime_error("Unknown address family");
    }
    buf[ARRLEN(buf)-1] = '\0';
    strm<<buf<<":"<<port;
    return strm;
}
