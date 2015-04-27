Fun with HTTP/2.0
=================

Experiments with nghttp2 [http://nghttp2.org/](http://nghttp2.org/)

Requires:

* libevent >= 2.0.19
* nghttp2 >= 0.7.11

```shell
git clone https://github.com/mdavidsaver/h2test.git
cd h2test/src
mkdir build
cd build
cmake .. -DNGHTTP2_DIR=/path/to/nghttp2/usr
make
```

testserver
----------

```shell
./testserver 127.0.0.1:5678
```

Server providing several urls.  See [src/testserver.cpp](src/testserver.cpp)

* /hello - Returns a string
* /spam - Returns a counter, runs as fast as the client allows
* /tick - Returns a counter, one line per second.

client
------

```shell
./client 127.0.0.1 5678 /hello
```

Client which fetches a single stream, rate limited to 100 bytes per second.  See [src/demo/client.c](src/demo/client.c).


Older tests
-----------

* server404 - Returns 404 for all requests
* serverspam - Same as testserver w/ /spam
* servertick - Same as testserver w/ /tick
