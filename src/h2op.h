#ifndef H2OP_H
#define H2OP_H

#include <ostream>
#include <string>
#include <list>
#include <map>

#include <event2/util.h>
#include <event2/buffer.h>
#include <event2/bufferevent.h>
#include <event2/listener.h>

namespace H2 {

class EventSignal
{
public:
    struct Handler
    {
        virtual ~Handler(){}
        virtual void signal(int signum)=0;
    };

    EventSignal(event_base *base, int signum, Handler* =0);
    ~EventSignal();
private:
    event_base *base;
    event *sig;
    Handler *H;
    static void sighandle(evutil_socket_t s, short evt, void *raw);
};

struct Transport;
struct RawRequest;

struct URL
{
    std::string scheme, authority, path;
};

union sockaddr_pun {
    sockaddr_storage store;
    sockaddr_in in;
    sockaddr_in6 in6;
};
} // namespace H2

namespace std {
template<> struct less<H2::sockaddr_pun> {
    inline bool operator ()(const H2::sockaddr_pun& A, const H2::sockaddr_pun& B)
    { return evutil_sockaddr_cmp((const sockaddr*)&A, (const sockaddr*)&B, 1)<0; }
};
}

namespace H2 {

struct RequestInfo
{
    sockaddr_pun peer, self;
    std::string method;
    URL url;

    typedef std::list<std::string> header_list_t;
    typedef std::map<std::string, header_list_t > headers_t;
    headers_t headers;
};

struct Request
{
    virtual ~Request();
    virtual void cancel()=0;
};

class Stream
{
    RawRequest *req;
    friend class RawRequest;
public:
    typedef RequestInfo::headers_t headers_t;

    virtual ~Stream() {}
    bufferevent *bev();

    void set_tx_eoi();
    bool tx_eoi() const;
    void set_rx_buffer(size_t low, size_t high);
    void set_tx_buffer(size_t low);

    virtual void send_headers(unsigned int status, const headers_t&);

    virtual void start() {}
    virtual void tx() {}
    virtual void rx() {}
    virtual void rx_eoi() {}
    virtual void closed() {}
};

class Handler
{
public:
    struct Config
    {
        Config() :tx_enabled(false), rx_enabled(false) {}
        bool tx_enabled, rx_enabled;
        //! Indicate that this Stream will write data to it's bufferevent
        Config& enable_tx(bool v=true) {tx_enabled=v; return *this;}
        //! Indicate that this Stream will read data from it's bufferevent
        Config& enable_rx(bool v=true) {rx_enabled=v; return *this;}
    };

    virtual ~Handler(){}
    virtual Stream* build(const RequestInfo&, Config&)=0;
    virtual void aborted() {}
};

class Client
{
public:
    typedef RequestInfo::headers_t headers_t;

    Client(event_base*);
    ~Client();

    Request* request(const char *op, Handler*, const URL&, const headers_t&);
};

struct ServerTransport;
struct ServerRequest;

class Server
{
public:
    Server(event_base*, unsigned short port);
    Server(event_base*, const std::string& iface, unsigned short dftport);
    Server(event_base*, const sockaddr_pun&);
    ~Server();

    void set_handler(std::string path, Handler*);

private:
    friend struct ServerRequest;
    friend struct ServerTransport;

    event_base *base;
    struct evconnlistener *listener;
    void setupSock(const sockaddr_pun&);

    static void newconn(struct evconnlistener *lev, evutil_socket_t sock, struct sockaddr *cli, int socklen, void *raw);
    static void listenerr(struct evconnlistener *lev, void *raw);

    typedef std::map<std::string, Handler*> handlers_t;
    handlers_t handlers;
    typedef std::map<sockaddr_pun, ServerTransport*> conns_t;
    conns_t conns;
};

} // namespace H2

std::ostream& operator<<(std::ostream& strm, const H2::sockaddr_pun& addr);

#endif // H2OP_H
