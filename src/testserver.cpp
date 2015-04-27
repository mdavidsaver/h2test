
#include <stdio.h>
#include <memory>
#include <signal.h>

#include <assert.h>

#include "h2op.h"

namespace {
class HelloHandle : public H2::Handler
{
    class Stream : public H2::Stream
    {
        virtual void start()
        {
            evbuffer *buf = bufferevent_get_output(bev());
            evbuffer_add_printf(buf, "Hello world\n");
            bufferevent_flush(bev(), EV_WRITE, BEV_FINISHED);
            H2::Stream::headers_t H;
            H["Content-Type"] = H2::Stream::headers_t::mapped_type();
            H["Content-Type"].push_back("text/ascii");
            send_headers(200, H);
        }
    };

    virtual ~HelloHandle() {}
    virtual H2::Stream* build(const H2::RequestInfo &I, Config &C)
    {
        C.enable_tx();
        return new Stream();
    }
};
} // namespace

int main(int argc, char *argv[])
{
    if(argc<=1) {
        fprintf(stderr, "Usage: %s <addr[:port]>\n", argv[0]);
        return 1;
    }
    event_base *base = event_base_new();
    assert(base);
    int ret = 0;
    try{
        std::auto_ptr<H2::Server> serv(new H2::Server(base, argv[1], 5678));

        serv->set_handler("/hello", new HelloHandle());

        H2::EventSignal sigint(base, SIGINT), sigquit(base, SIGQUIT);

        printf("Running\n");
        event_base_loop(base, 0);
    }catch(std::exception& e){
        fprintf(stderr, "Unhandled exception: %s\n", e.what());
        ret = 2;
        printf("Cleanup\n");
        const timeval timo={0,1};
        event_base_loopexit(base, &timo);
        event_base_loop(base, 0);
    }

    printf("Done\n");

    event_base_free(base);
    return ret;
}
