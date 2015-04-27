
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <assert.h>

#include <vector>

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
        H2::Transport::InCallback incb(sock);

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

        nghttp2_session_consume_connection(sock->h2sess, consumed);

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
    printf("%s Tx produce %lu %lu/%lu\n", self->myname.c_str(),
           (unsigned long)length,
           (unsigned long)nghttp2_session_get_outbound_queue_size(self->h2sess),
           (unsigned long)nghttp2_session_get_remote_window_size(self->h2sess));
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

    std::string hname((const char*)name, namelen),
                hval((const char*)value, valuelen);

    if(name[0]==':') { // handle pseudo headers
        if(namelen<2) return 0;

        switch(name[1]) {
        case 'a':
            if(hname==":authority")
                req->info.url.authority.swap(hval);
            break;
            /*
        case 'e':
            if(hname==":expect" && hval=="100-continue") {
                //TODO: send 100 continue
                fprintf(stderr, "Peer requested 100-continue, TODO: send it\n");
            }
            break;
            */
        case 'm':
            if(hname==":method")
                req->info.method.swap(hval);
            break;
        case 'p':
            if(hname==":path")
                req->info.url.path.swap(hval);
            break;
        case 's':
            if(hname==":scheme")
                req->info.url.scheme.swap(hval);
            break;
        default:
            req->handle_pseudo_header(hname, hval);
        }

    } else {

        H2::RequestInfo::header_list_t *hlist;

        H2::RequestInfo::headers_t::iterator it = req->info.headers.find(hname);
        if(it==req->info.headers.end()) {
            req->info.headers[hname] = H2::RequestInfo::header_list_t();
            hlist = &req->info.headers[hname];
        } else
            hlist = &it->second;

        hlist->push_back(hval);
    }
    return 0;
}

static const char* frame_names[] = {
    "DATA",
    "HEAD",
    "PRIO",
    "RST ",
    "SETT",
    "PUSH",
    "PING",
    "GOWY",
    "WIND"
};

static
void debug_frame(const char *dir, H2::Transport *sock, const nghttp2_frame *frame)
{
    const char *name = sock->myname.c_str(),
               *ftype = "???";

    if(frame->hd.type<ARRLEN(frame_names))
        ftype = frame_names[frame->hd.type];

    printf("%s: %s %s stream=%lu flags=0x%02x length=%lu ",
           name, dir, ftype,
           (unsigned long)frame->hd.stream_id,
           frame->hd.flags,
           (unsigned long)frame->hd.length);

    if(frame->hd.type>=ARRLEN(frame_names))
        printf("ftype=%d ",
               frame->hd.type);

    switch(frame->hd.type) {
    case NGHTTP2_RST_STREAM:
        printf("error=%u\n", frame->rst_stream.error_code);
        break;
    case NGHTTP2_GOAWAY:
        printf("error=%u last=%lu %s\n",
               frame->goaway.error_code,
               (unsigned long)frame->goaway.last_stream_id,
               (char*)frame->goaway.opaque_data);
        break;
    default:
        printf("\n");
    }
}

static
int on_frame_recv_callback(nghttp2_session *h2sess,
                           const nghttp2_frame *frame, void *raw)
{
    H2::Transport *sock = (H2::Transport*)raw;
    H2::RawRequest *req = NULL;
    bool reset_stream = false;

    assert(sock->h2sess==h2sess);

    debug_frame("recv", sock, frame);

    switch(frame->hd.type) {
    case NGHTTP2_HEADERS:
        if(frame->hd.flags & NGHTTP2_FLAG_END_HEADERS)
        {
            if(!req) req = (H2::RawRequest*)nghttp2_session_get_stream_user_data(h2sess, frame->hd.stream_id);

            if(req) {
                assert(req->streamid==frame->hd.stream_id);
                try{
                    req->end_of_headers();
                }catch(std::exception& e){
                    fprintf(stderr, "%s: Unhandled exception in RawRequest::end_of_headers: %s",
                            sock->myname.c_str(), e.what());
                    reset_stream = true;
                }
            }

        }
        /* no break */
    case NGHTTP2_DATA:

        if(frame->hd.flags & NGHTTP2_FLAG_END_STREAM)
        {
            if(!req) req = (H2::RawRequest*)nghttp2_session_get_stream_user_data(h2sess, frame->hd.stream_id);

            if(req) {
                try{
                    req->end_of_data();
                }catch(std::exception& e){
                    fprintf(stderr, "%s: Unhandled exception in RawRequest::end_of_data: %s",
                            sock->myname.c_str(), e.what());
                    reset_stream = true;
                }
            }
        }
        break;
    case NGHTTP2_RST_STREAM:
        if(frame->rst_stream.error_code)
            fprintf(stderr, "Stream %d reset %d\n", frame->hd.stream_id,
                    frame->rst_stream.error_code);
        break;
    case NGHTTP2_GOAWAY:
    {
        char *buf = (char*)malloc(frame->goaway.opaque_data_len+1);
        if(buf) {
            memcpy(buf, frame->goaway.opaque_data, frame->goaway.opaque_data_len);
            buf[frame->goaway.opaque_data_len] = '\0';
        }
        fprintf(stderr, "%s: Go away: last=%d error=%d: %s\n", sock->myname.c_str(),
                frame->goaway.last_stream_id,
                frame->goaway.error_code, buf);
        free(buf);
    }
        break;
    default:
        break;
    }

    if(reset_stream) {
        return nghttp2_submit_rst_stream(h2sess, NGHTTP2_FLAG_NONE,
                                         frame->hd.stream_id, NGHTTP2_ERR_INVALID_ARGUMENT);
    }
    return 0;
}

static
int on_frame_send_callback(nghttp2_session *session,
                           const nghttp2_frame *frame,
                           void *raw)
{
    H2::Transport *sock = (H2::Transport*)raw;

    assert(sock->h2sess==session);

    debug_frame("send", sock, frame);
    return 0;
}

static
int stream_read(nghttp2_session *session,
                uint8_t flags,
                int32_t stream_id,
                const uint8_t *data,
                size_t len, void *raw)
{
    H2::Transport *sock = (H2::Transport*)raw;
    H2::RawRequest *req = (H2::RawRequest*)nghttp2_session_get_stream_user_data(session, stream_id);
    if(!req) return 0;

    assert(sock->h2sess==session);
    assert(req->sock==sock);
    assert(req->streamid==stream_id);

    if(req->rxeoi) return 0; // ignore further

    if(bufferevent_write(req->sock_bev, data, len)) {
        fprintf(stderr, "%s: failed to add stream data\n", sock->myname.c_str());
        return nghttp2_submit_rst_stream(session, NGHTTP2_FLAG_NONE,
                                         stream_id, NGHTTP2_ERR_INVALID_ARGUMENT);
    }
    return 0;
}

static
int stream_end(nghttp2_session *session, int32_t stream_id,
               uint32_t error_code, void *raw)
{
    H2::Transport *sock = (H2::Transport*)raw;
    H2::RawRequest *req = (H2::RawRequest*)nghttp2_session_get_stream_user_data(session, stream_id);
    if(!req) return 0;

    assert(sock->h2sess==session);
    assert(req->sock==sock);
    assert(req->streamid==stream_id);

    sock->active_requests.erase(req);
    try{
        printf("%s: stream %d ends request %p\n", sock->myname.c_str(), req->streamid, req);
        if(!req->rxeoi)
            req->end_of_data();
        if(req->user)
            req->user->closed();
        delete req;
    }catch(std::exception& e){
        fprintf(stderr, "%s: Unhandled exception during stream cleanup %s\n",
                sock->myname.c_str(), e.what());
    }
    return 0;
}

static
void deferred_send(evutil_socket_t s, short evt, void *raw)
{
    H2::Transport *self=(H2::Transport*)raw;
    if(!self->queuesend) return;
    self->queuesend = false;
    int ret = nghttp2_session_send(self->h2sess);
    if(ret)
        fprintf(stderr, "%s: Failed deferred send\n", self->myname.c_str());
}

namespace H2 {

Transport::Transport(event_base *base)
    :base(base)
    ,bev(0)
    ,h2sess(0)
    ,deferedsend(event_new(base, -1, EV_TIMEOUT, deferred_send, this))
    ,sendwait(false)
    ,incb(false)
    ,queuesend(false)
{
    if(!deferedsend)
        throw std::bad_alloc();
}

Transport::~Transport()
{
    nghttp2_session_del(h2sess);
    if(bev) bufferevent_free(bev);
    event_free(deferedsend);
    if(active_requests.size())
        fprintf(stderr, "%s: cleaning %lu active streams\n", myname.c_str(),
                (unsigned long)active_requests.size());
    std::set<RawRequest*>::iterator it, end;
    for(it=active_requests.begin(), end=active_requests.end(); it!=end; ++it)
    {
        delete *it;
    }
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
    nghttp2_session_callbacks_set_on_header_callback(callbacks, stream_header);
    nghttp2_session_callbacks_set_on_stream_close_callback(callbacks, stream_end);
    nghttp2_session_callbacks_set_on_frame_recv_callback(callbacks, on_frame_recv_callback);
    nghttp2_session_callbacks_set_on_frame_send_callback(callbacks, on_frame_send_callback);
    nghttp2_session_callbacks_set_on_data_chunk_recv_callback(callbacks, stream_read);
}

void Transport::queue_deferred_send()
{
    const timeval now = {0,0};
    if(incb || queuesend) return;
    if(!event_add(deferedsend, &now))
        queuesend = true;
}

void Transport::send_now()
{
    int ret = nghttp2_session_send(h2sess);
    if(ret)
        throw std::runtime_error("Transport send fails");
}

ssize_t Transport::stream_write(nghttp2_session *session, int32_t stream_id,
                     uint8_t *buf, size_t length,
                     uint32_t *data_flags,
                     nghttp2_data_source *source, void *raw)
{
    Transport *sock = (Transport*)raw;
    RawRequest *req = (RawRequest*)source->ptr;
    if(!req) {
        *data_flags = NGHTTP2_DATA_FLAG_EOF;
        return 0;
    }

    assert(sock->h2sess==session);
    assert(req->sock==sock);
    assert(req->streamid==stream_id);
    assert(req==(H2::RawRequest*)nghttp2_session_get_stream_user_data(session, stream_id));
    printf("%s stream %d %p write ", sock->myname.c_str(), stream_id, req);

    if(!req->user) {
        *data_flags = NGHTTP2_DATA_FLAG_EOF;
        printf("EOF orphaned stream\n");
        return 0;
    }

    //Stream *strm = req->user;

    evbuffer *ebuf = bufferevent_get_input(req->sock_bev);
    size_t blen = evbuffer_get_length(ebuf);

    if(req->txeoi) {
        printf("EOF\n");
        *data_flags = NGHTTP2_DATA_FLAG_EOF;
        return 0;
    } else if(req->txpaused || blen==0) {
        printf("Pause\n");
        req->txpaused = true;
        return NGHTTP2_ERR_DEFERRED;
    }
    size_t tosend = std::min(length, blen);
    ssize_t nsent = evbuffer_copyout(ebuf, buf, tosend);
    if(nsent<0) {
        printf("Error\n");
        fprintf(stderr, "%s: failed to send stream data\n", sock->myname.c_str());
        return nghttp2_submit_rst_stream(session, NGHTTP2_FLAG_NONE,
                                         stream_id, NGHTTP2_ERR_INVALID_ARGUMENT);
    }
    printf("length=%lu\n",(unsigned long)nsent);
    evbuffer_drain(ebuf, nsent);
    return nsent;
}

bufferevent* Stream::bev()
{
    return req->user_bev;
}

void Stream::set_tx_eoi()
{
    req->txeoi = true;
}

bool Stream::tx_eoi() const
{
    return req->txeoi;
}

void Stream::set_rx_buffer(size_t low, size_t high)
{
    //TODO
}

void Stream::send_headers(unsigned int status, const headers_t& H)
{
    assert(req->user==this);
    if(req->sentheaders)
        throw std::runtime_error("Headers already sent");

    char stsbuf[12];
    sprintf(stsbuf, "%d", status&0xffffffff);

    std::vector<nghttp2_nv> nH;
    nH.reserve(H.size()+1);
    nH.resize(1);
    nH[0].name = (uint8_t*)":status";
    nH[0].namelen = 7;
    nH[0].value = (uint8_t*)stsbuf;
    nH[0].valuelen = strlen(stsbuf);

    for(headers_t::const_iterator it = H.begin(), end = H.end();it!=end;++it)
    {
        const std::string& N = it->first;
        const RequestInfo::header_list_t& V = it->second;
        nH.reserve(nH.size()+V.size());

        for(RequestInfo::header_list_t::const_iterator lit = V.begin(), lend = V.end(); lit!=lend; ++lit)
        {
            nH.push_back(nghttp2_nv());
            nghttp2_nv& O = nH.back();
            O.name = (uint8_t*)N.c_str();
            O.namelen = N.size();
            O.value = (uint8_t*)lit->c_str();
            O.valuelen = lit->size();
        }

        //TODO: mark none cachable headers?
    }

    nghttp2_data_provider prov;
    prov.source.ptr = req;
    prov.read_callback = &Transport::stream_write;
    if(req->txeoi && evbuffer_get_length(bufferevent_get_output(req->sock_bev))==0)
        prov.read_callback = NULL; // no data to send
    else
        bufferevent_enable(req->sock_bev, EV_READ);

    printf("%s: stream send headers %d %p\n", req->sock->myname.c_str(), req->streamid, req);
    int ret = nghttp2_submit_response(req->sock->h2sess, req->streamid, &nH[0], nH.size(), &prov);
    req->sentheaders = true;
    if(ret) {
        fprintf(stderr, "%s: failed to send stream data: %d\n", req->sock->myname.c_str(), ret);
        nghttp2_submit_rst_stream(req->sock->h2sess, NGHTTP2_FLAG_NONE,
                                  req->streamid, ret);
    } else
        req->sock->queue_deferred_send();
}

} // namespace H2


std::ostream& operator<<(std::ostream& strm, const H2::sockaddr_pun& addr)
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
