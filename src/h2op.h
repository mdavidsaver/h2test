#ifndef H2OP_H
#define H2OP_H

#include <string>
#include <list>
#include <map>

#include <event2/util.h>
#include <event2/buffer.h>

namespace H2 {

struct Transport;

struct URL
{
    std::string scheme, authority, path;
};

struct RequestInfo
{
    sockaddr_storage peer, self;
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
    Transport *sock;
    friend class Transport;

    evbuffer *buf_tx, *buf_rx;
    bool txpaused, txeoi, rxeoi;
    size_t rxlow, rxhigh;
public:
    inline evbuffer *tx_buffer() {return buf_tx;}
    inline evbuffer *rx_buffer() {return buf_rx;}

    void set_tx_eoi();
    inline bool tx_eof() const {return txeoi;}
    void set_tx_buffer(size_t low, size_t high);

    virtual void rx(unsigned len);
    virtual void rx_eoi();
    virtual void closed();
};

class Handler
{
public:
    virtual Stream* build(const RequestInfo&)=0;
    virtual void aborted() {}
};

class Client
{
public:
    typedef RequestInfo::headers_t headers_t;

    Client(event_base*);
    ~Client();

    void bind(sockaddr_storage& addr);

    Request* request(const char *op, Handler*, const URL&, const headers_t*);
};

class Server
{
public:
    Server(event_base*);
    ~Server();

    void set_handler(std::string path, Handler*);
};

} // namespace H2

#endif // H2OP_H
