#ifndef AGENT_H
#define AGENT_H

#include <queue>
#include <string>
#include <functional>
#include <uv.h>
#include <openssl/ossl_typ.h>

#include "WebSocket.h"

namespace uWS {

enum Error {
    ERR_LISTEN,
    ERR_SSL
};

enum Options : int {
    NO_OPTIONS = 0,
    PERMESSAGE_DEFLATE = 1,
    SERVER_NO_CONTEXT_TAKEOVER = 2,
    CLIENT_NO_CONTEXT_TAKEOVER = 4,
    NO_DELAY = 8
};

class SSLContext {
private:
    SSL_CTX *sslContext = nullptr;
public:
    SSLContext(std::string certFileName, std::string keyFileName);
    SSLContext() = default;
    SSLContext(const SSLContext &other);
    ~SSLContext();
    operator bool() {
        return sslContext;
    }
    void *newSSL(int fd);
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
    bool master, forceClose;
    int options, maxPayload;
	SSLContext sslContext;
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
    Agent(bool master, int options = 0, int maxPayload = 1048576, SSLContext sslContext = SSLContext()) : master(master), options(options), maxPayload(maxPayload), sslContext(sslContext) {};
    Agent(const Agent &server) = delete;
    Agent &operator=(const Agent &server) = delete;
    void onConnection(std::function<void(WebSocket<IsServer>)> connectionCallback);
    void onDisconnection(std::function<void(WebSocket<IsServer>, int code, char *message, size_t length)> disconnectionCallback);
    void onMessage(std::function<void(WebSocket<IsServer>, char *, size_t, OpCode)> messageCallback);
	void onPing(std::function<void(WebSocket<IsServer>, char *, size_t)> pingCallback);
	void onPong(std::function<void(WebSocket<IsServer>, char *, size_t)> pongCallback);
    void close(bool force = false);
    void run();
    void broadcast(char *data, size_t length, OpCode opCode);
};

}

#endif // AGENT_H
