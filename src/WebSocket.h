#ifndef WEBSOCKET_H
#define WEBSOCKET_H

#include <functional>
#include <uv.h>

namespace uWS {

enum OpCode : unsigned char {
    TEXT = 1,
    BINARY = 2,
    CLOSE = 8,
    PING = 9,
    PONG = 10
};

template <bool IsServer>
class Agent;

class Server;

struct Address {
    unsigned int port;
    char *address;
    const char *family;
};

struct PreparedMessage {
    char *buffer;
    size_t length;
    int references;
};

template <bool IsServer>
class WebSocket
{
    friend class Server;
    friend class Client;
    friend struct Parser;
    template <bool IsServer2> friend class Agent;
    friend struct std::hash<uWS::WebSocket<IsServer>>;
private:
    static void onReadable(uv_poll_t *p, int status, int events);
    void initPoll(Agent<IsServer> *agent, uv_os_sock_t fd, void *ssl, void *perMessageDeflate);
    void link(uv_poll_t *next);
    uv_poll_t *next();
    operator bool();
    void write(char *data, size_t length, bool transferOwnership, void(*callback)(WebSocket<IsServer> webSocket, void *data, bool cancelled) = nullptr, void *callbackData = nullptr, bool preparedMessage = false);
    void handleFragment(const char *fragment, size_t length, OpCode opCode, bool fin, size_t remainingBytes, bool compressed);
protected:
    uv_poll_t *p;
    WebSocket<IsServer>(uv_poll_t *p);
public:
    Address getAddress();
    void close(bool force = false, unsigned short code = 0, char *data = nullptr, size_t length = 0);
    void send(char *message, size_t length, OpCode opCode, void(*callback)(WebSocket<IsServer> webSocket, void *data, bool cancelled) = nullptr, void *callbackData = nullptr, size_t fakedLength = 0);
    void ping(char *message = nullptr, size_t length = 0);
    void sendFragment(char *data, size_t length, OpCode opCode, size_t remainingBytes);
    static PreparedMessage *prepareMessage(char *data, size_t length, OpCode opCode, bool compressed);
    void sendPrepared(PreparedMessage *preparedMessage);
    static void finalizeMessage(PreparedMessage *preparedMessage);
    void *getData();
    void setData(void *data);
    WebSocket<IsServer>() : p(nullptr) {}
    bool operator==(const WebSocket<IsServer> &other) const {return p == other.p;}
    bool operator<(const WebSocket<IsServer> &other) const {return p < other.p;}
};
typedef WebSocket<true> ServerSocket;
typedef WebSocket<false> ClientSocket;

}

namespace std {

template <>
struct hash<uWS::WebSocket<true>> {
    std::size_t operator()(const uWS::WebSocket<true> &webSocket) const
    {
        return std::hash<uv_poll_t *>()(webSocket.p);
    }
};
template <>
struct hash<uWS::WebSocket<false>> {
    std::size_t operator()(const uWS::WebSocket<false> &webSocket) const
    {
        return std::hash<uv_poll_t *>()(webSocket.p);
    }
};

}

#endif // WEBSOCKET_H
