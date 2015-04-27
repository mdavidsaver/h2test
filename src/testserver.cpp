
#include <stdio.h>
#include <signal.h>
#include <assert.h>

#include <memory>
#include <stdexcept>

#include "h2op.h"

namespace {
/** Reply with a static string
 */
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
            H["content-type"] = H2::Stream::headers_t::mapped_type();
            H["content-type"].push_back("text/ascii");
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

/** Write back a counter as fast as possible */
class CountSpam : public H2::Handler
{
    class Stream : public H2::Stream
    {
        unsigned long count;
        static void write_cb(struct bufferevent *bev, void *raw)
        {
            Stream *self = (Stream*)raw;
            evbuffer *buf = bufferevent_get_output(bev);
            while(evbuffer_get_length(buf)<128)
            {
                evbuffer_add_printf(buf, "%lu\n", self->count++);
            }
        }

        virtual void start()
        {
            bufferevent *bev = this->bev();
            bufferevent_setcb(bev, NULL, write_cb, NULL, this);
            bufferevent_setwatermark(bev, EV_WRITE, 128, 0);

            write_cb(bev, this); // prime the buffer

            H2::Stream::headers_t H;
            H["content-type"] = H2::Stream::headers_t::mapped_type();
            H["content-type"].push_back("text/ascii");
            send_headers(200, H);
        }
    public:
        Stream()
            :count(0)
        {}
    };
    virtual ~CountSpam() {}
    virtual H2::Stream* build(const H2::RequestInfo &, Config &C)
    {
        C.enable_tx();
        return new Stream();
    }
};

/** Write back a counter at ~1Hz */
class CountTick : public H2::Handler
{
    class Stream : public H2::Stream
    {
        unsigned long count;
        event *tick;
        static void tick_cb(evutil_socket_t s, short evt, void *raw)
        {
            printf("Tick\n");
            Stream *self = (Stream*)raw;
            evbuffer *buf = bufferevent_get_output(self->bev());
            evbuffer_add_printf(buf, "%lu\n", self->count++);
        }

        virtual void start()
        {
            const timeval interval = {1,0};
            if(event_add(tick, &interval))
                throw std::runtime_error("Failed to add timer event");

            H2::Stream::headers_t H;
            H["content-type"] = H2::Stream::headers_t::mapped_type();
            H["content-type"].push_back("text/ascii");
            send_headers(200, H);
        }
    public:
        Stream(event_base *base)
            :count(0)
            ,tick(event_new(base, -1, EV_TIMEOUT|EV_PERSIST, tick_cb, this))
        {
            if(!tick)
                throw std::bad_alloc();
        }
        ~Stream()
        {
            event_free(tick);
        }
    };
    event_base *base;
    virtual ~CountTick() {}
    virtual H2::Stream* build(const H2::RequestInfo &, Config &C)
    {
        C.enable_tx();
        return new Stream(base);
    }
public:
    CountTick(event_base *base) :base(base) {}
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
        serv->set_handler("/spam", new CountSpam());
        serv->set_handler("/tick", new CountTick(base));

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
