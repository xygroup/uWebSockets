#ifndef AGENT_H
#define AGENT_H

#include <queue>
#include <string>
#include <functional>

#ifndef NO_OPENSSL
#include <openssl/ossl_typ.h>
#endif

#ifdef BAZEL
    #include "libuv/uv.h"
    #include "external/zlib/zlib.h"
#else
    #include <uv.h>
    #include <zlib.h>
#endif

#include "Network.h"
#include "WebSocket.h"

namespace uWS {

enum Error {
    ERR_LISTEN,
    ERR_SSL,
	ERR_ZLIB
};

enum Options : unsigned int {
    NO_OPTIONS = 0,
    PERMESSAGE_DEFLATE = 1,
    SERVER_NO_CONTEXT_TAKEOVER = 2,
    CLIENT_NO_CONTEXT_TAKEOVER = 4,
    NO_DELAY = 8
};

#ifndef NO_OPENSSL
class SSLContext {
private:
    SSL_CTX *sslContext = nullptr;
public:
    SSLContext(std::string certChainFileName, std::string keyFileName);
    SSLContext() = default;
    SSLContext(const SSLContext &other);
    ~SSLContext();
    operator bool() {
        return sslContext;
    }
    void *newSSL(int fd);
};
#endif

template <bool IsServer>
struct WebSocketIterator {
	WebSocket<IsServer> webSocket;
	WebSocketIterator(WebSocket<IsServer> webSocket) : webSocket(webSocket) {

	}

	WebSocket<IsServer> &operator*() {
		return webSocket;
	}

	bool operator!=(const WebSocketIterator<IsServer> &other) {
		return !(webSocket == other.webSocket);
	}

	WebSocketIterator<IsServer> &operator++() {
		webSocket = webSocket.next();
		return *this;
	}
};

template <bool IsServer>
class Agent
{
    template <bool IsServer2> friend class WebSocket;
    friend class Server;
    friend class Client;
    friend class HTTPSocket;
protected:
    uv_loop_t *loop;
    uv_poll_t *clients = nullptr;
    uv_async_t closeAsync;
	z_stream writeStream;
    bool master, forceClose;
    unsigned int options, maxPayload;
#ifndef NO_OPENSSL
    SSLContext sslContext;
#endif
    static void closeHandler(Agent<IsServer> *agent);

    char *recvBuffer, *sendBuffer, *inflateBuffer;
    static const int LARGE_BUFFER_SIZE = 307200,
                     SHORT_BUFFER_SIZE = 4096;

    std::function<void(WebSocket<IsServer>)> connectionCallback;
    std::function<void(WebSocket<IsServer>, int code, char *message, size_t length)> disconnectionCallback;
    std::function<void(WebSocket<IsServer>, char *, size_t, OpCode)> messageCallback;
    std::function<void(WebSocket<IsServer>, char *, size_t)> pingCallback;
    std::function<void(WebSocket<IsServer>, char *, size_t)> pongCallback;
public:
#ifndef NO_OPENSSL
    Agent(bool master, unsigned int options = 0, unsigned int maxPayload = 1048576, SSLContext sslContext = SSLContext()) : master(master), options(options), maxPayload(maxPayload), sslContext(sslContext) {};
#else
    Agent(bool master, unsigned int options = 0, unsigned int maxPayload = 1048576) : master(master), options(options), maxPayload(maxPayload) {};
#endif
    Agent(const Agent &server) = delete;
    Agent &operator=(const Agent &server) = delete;
    void onConnection(std::function<void(WebSocket<IsServer>)> connectionCallback);
    void onDisconnection(std::function<void(WebSocket<IsServer>, int code, char *message, size_t length)> disconnectionCallback);
    void onMessage(std::function<void(WebSocket<IsServer>, char *, size_t, OpCode)> messageCallback);
    void onPing(std::function<void(WebSocket<IsServer>, char *, size_t)> pingCallback);
    void onPong(std::function<void(WebSocket<IsServer>, char *, size_t)> pongCallback);
    void close(bool force = false);
    void run();
	size_t compress(char *src, size_t srcLength, char *dst);
    void broadcast(char *data, size_t length, OpCode opCode);

    WebSocketIterator<IsServer> begin() {
        return WebSocketIterator<IsServer>(clients);
    }

    WebSocketIterator<IsServer> end() {
        return WebSocketIterator<IsServer>(nullptr);
    }
};

}

#endif // AGENT_H
