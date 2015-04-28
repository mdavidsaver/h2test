
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <assert.h>

#include <sstream>
#include <memory>

#include "h2internal.h"

#define ARRLEN(x) (sizeof(x) / sizeof(x[0]))

namespace {
struct Stream404 : public H2::Stream
{
    Stream404()
        :H2::Stream()
    {
    }
    virtual void start()
    {
        bufferevent_enable(bev(), EV_READ);
        // no data
        if(bufferevent_flush(bev(), EV_WRITE, BEV_FINISHED))
            throw std::logic_error("404 failed to flush stream");

        headers_t H;
        send_headers(404, H);
    }
};

struct Handle404 : public H2::Handler
{
    virtual ~Handle404(){}
    virtual H2::Stream* build(const H2::RequestInfo& i, Config& c)
    {
        return new Stream404();
    }
};
}

static
void pingconn(evutil_socket_t s, short evt, void *raw)
{
    H2::ServerTransport *self = (H2::ServerTransport *)raw;
    if(nghttp2_submit_ping(self->h2sess, 0, NULL) ||
            nghttp2_session_send(self->h2sess))
    {
        fprintf(stderr, "%s: ping failed\n", self->myname.c_str());
    }
}

namespace H2 {
struct ServerRequest : H2::RawRequest
{
    ServerRequest(H2::Transport *s, int32_t id) : H2::RawRequest(s,id) {}
    virtual ~ServerRequest() {}

    virtual void handle_pseudo_header(const std::string& name, const std::string& value)
    {
        //TODO: handle 100-continue
    }

    virtual void end_of_headers()
    {
        ServerTransport *TR = static_cast<ServerTransport*>(sock);

        Handle404 notfound;

        Handler *H = &notfound;
        H2::Server::handlers_t::const_iterator it = TR->server->handlers.find(info.url.path);
        if(it!=TR->server->handlers.end()) {
            H = it->second;
        }
        H2::Handler::Config conf;
        set_user(H->build(info, conf));
        //TODO: send 100-continue now
        if(conf.rx_enabled) {
            bufferevent_enable(sock_bev, EV_READ);
        } else {
            rxeoi = true;
            bufferevent_flush(sock_bev, EV_WRITE, BEV_FINISHED);
        }
        if(!conf.tx_enabled) {
            txeoi = true;
            bufferevent_flush(sock_bev, EV_READ, BEV_FINISHED);
        }
        user->start();
    }

    virtual void end_of_data()
    {
        if(!rxeoi)
            bufferevent_flush(sock_bev, EV_WRITE, BEV_FINISHED);
        rxeoi = true;
        if(user) {
            user->closed();
        }
    }
};
} // namespace H2

static
int stream_begin(nghttp2_session *session,
                 const nghttp2_frame *frame,
                 void *raw)
{
    H2::Transport *sock = (H2::Transport*)raw;

    assert(sock->h2sess==session);
    assert(nghttp2_session_get_stream_user_data(session, frame->hd.stream_id)==NULL);
    try{
        H2::ServerRequest *req = new H2::ServerRequest(sock, frame->hd.stream_id);
        assert(req->streamid==frame->hd.stream_id);
        nghttp2_session_set_stream_user_data(session, frame->hd.stream_id, static_cast<H2::RawRequest*>(req));
        sock->active_requests.insert(req);
        printf("%s: stream %d begins request %p\n", sock->myname.c_str(), req->streamid, req);
    }catch(std::exception&){
        fprintf(stderr, "%s: failed to create stream\n", sock->myname.c_str());
        return nghttp2_submit_rst_stream(session, NGHTTP2_FLAG_NONE,
                                         frame->hd.stream_id, NGHTTP2_ERR_INVALID_ARGUMENT);
    }
    return 0;
}

namespace H2 {

ServerTransport::ServerTransport(Server *serv,
                                 event_base *base,
                                 evutil_socket_t sock,
                                 const sockaddr_pun& peer)
    :Transport(base)
    ,server(serv)
{
    this->peer = peer;
    std::ostringstream strm;
    strm<<peer;
    myname = strm.str();
    printf("New connection: %s\n", myname.c_str());

    nghttp2_option *option = 0;
    nghttp2_session_callbacks *callbacks = 0;

    try{
        pingtimer = event_new(base, -1, EV_TIMEOUT|EV_PERSIST, pingconn, this);
        if(!pingtimer)
            throw std::bad_alloc();

        bev = bufferevent_socket_new(base, sock, BEV_OPT_CLOSE_ON_FREE);
        if(!bev)
            throw std::bad_alloc();
        setup_bev();

        if(nghttp2_option_new(&option) ||
           nghttp2_session_callbacks_new(&callbacks))
            throw std::bad_alloc();

        setup_ng2(callbacks, option);
        nghttp2_session_callbacks_set_on_begin_headers_callback(callbacks, stream_begin);

        if(nghttp2_session_server_new2(&h2sess, callbacks, this, option))
            throw std::bad_alloc();

        nghttp2_settings_entry iv[] = {
            {NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, 100000},
            {NGHTTP2_SETTINGS_ENABLE_PUSH, 0}
        };

        int rv;
        if ((rv=nghttp2_submit_settings(h2sess, NGHTTP2_FLAG_NONE, iv, ARRLEN(iv))) ||
                (rv=nghttp2_session_send(h2sess)))
        {
            fprintf(stderr, "%s: Error at server connection setup: %d",
                    myname.c_str(), rv);
            throw std::runtime_error("Server connection setup fails");
        }

        const timeval itvl = {10,0}; // half the timeout interval

        event_add(pingtimer, &itvl); // start keep-alive timer
        start_bev();

    }catch(...){
        if(pingtimer) event_free(pingtimer);
        nghttp2_session_del(h2sess);
        if(bev) bufferevent_free(bev);
        nghttp2_session_callbacks_del(callbacks);
        nghttp2_option_del(option);
        throw;
    }

    nghttp2_session_callbacks_del(callbacks);
    nghttp2_option_del(option);
}

ServerTransport::~ServerTransport()
{
    printf("%s: Destroy connection\n", myname.c_str());
    event_free(pingtimer);
}

void ServerTransport::destory()
{
    printf("%s: Lose connection\n", myname.c_str());
    server->conns.erase(peer);
    delete this; // suicide...
}

Server::Server(event_base *base, unsigned short port)
    :base(base)
{
    sockaddr_pun addr;
    memset(&addr, 0, sizeof(addr));
    addr.in.sin_family = AF_INET;
    addr.in.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.in.sin_port = htons(port);

    setupSock(addr);
}

Server::Server(event_base* base, const std::string& iface, unsigned short dftport)
    :base(base)
{
    sockaddr_pun addr;
    int alen = sizeof(addr);
    memset(&addr, 0, sizeof(addr));
    if(evutil_parse_sockaddr_port(iface.c_str(), (sockaddr*)&addr, &alen)) {
        std::ostringstream msg;
        msg<<"Invalid address: "<<iface;
        throw std::runtime_error(msg.str());
    }
    switch(addr.in.sin_family){
    case AF_INET: if(addr.in.sin_port==0) addr.in.sin_port = dftport; break;
    case AF_INET6:if(addr.in6.sin6_port==0) addr.in6.sin6_port = dftport; break;
    default: throw std::runtime_error("Unknown address family");
    }
    setupSock(addr);
}

Server::Server(event_base* base, const sockaddr_pun& addr)
    :base(base)
{
    setupSock(addr);
}

void Server::setupSock(const sockaddr_pun &addr)
{
    listener = evconnlistener_new_bind(base, newconn, this,
                                       LEV_OPT_CLOSE_ON_FREE | LEV_OPT_REUSEABLE,
                                       4, (struct sockaddr*)&addr, sizeof(addr));
    if(!listener) {
        std::ostringstream msg;
        msg<<"Failed to bind "<<addr<<" : "<<evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR());
        throw std::runtime_error(msg.str());
    }
    evconnlistener_set_error_cb(listener, listenerr);

}

Server::~Server()
{
    for(conns_t::iterator it=conns.begin(), end=conns.end(); it!=end; ++it)
    {
        try{
            delete it->second;
        }catch(std::exception& e){
            fprintf(stderr, "Exception during connection teardown: %s\n", e.what());
        }
    }
    conns.clear();
    for(handlers_t::iterator it=handlers.begin(), end=handlers.end(); it!=end; ++it)
    {
        delete it->second;
    }
    handlers.clear();
    evconnlistener_free(listener);
}

void Server::set_handler(std::string path, Handler* H)
{
    handlers_t::iterator it = handlers.find(path);
    if(it!=handlers.end()) {
        Handler *oldH = it->second;
        handlers.erase(it);
        delete oldH;
    }
    handlers[path] = H;
}

void Server::newconn(evconnlistener *lev, int sock, sockaddr *cli, int socklen, void *raw)
{
    Server *self = (Server*)raw;
    sockaddr_pun addr;
    memcpy(&addr, cli, socklen);

    conns_t::const_iterator it = self->conns.find(addr);
    if(it!=self->conns.end()) {
        fprintf(stderr, "Socket already in open???\n");
        evutil_closesocket(sock);
        return;
    }

    ServerTransport *TR = new ServerTransport(self, self->base, sock, addr);
    self->conns[addr] = TR;
}

void Server::listenerr(evconnlistener *lev, void *raw)
{
    //Server *self = (Server*)raw;
    fprintf(stderr, "Server listen error %s\n",
            evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()));
}

} // namespace H2
