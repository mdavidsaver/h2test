
#include <stdio.h>
#include <string.h>
#include <errno.h>

#include <sstream>

#include "h2internal.h"

#define ARRLEN(x) (sizeof(x) / sizeof(x[0]))

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

ServerTransport::ServerTransport(Server *serv,
                                 event_base *base,
                                 evutil_socket_t sock,
                                 const sockaddr_pun& peer)
    :server(serv)
{
    std::ostringstream strm;
    strm<<peer;
    myname = strm.str();

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

        if(nghttp2_session_server_new2(&h2sess, callbacks, this, option))
            throw std::bad_alloc();

        nghttp2_settings_entry iv[] = {
            {NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, 10000},
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
    event_free(pingtimer);
    nghttp2_session_del(h2sess);
    bufferevent_free(bev);
}

} // namespace H2
