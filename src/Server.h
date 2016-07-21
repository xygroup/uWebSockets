#ifndef SERVER_H
#define SERVER_H

#include <mutex>
#include <queue>
#include <string>
#include <functional>
#include <uv.h>
#include <openssl/ossl_typ.h>

#include "Agent.h"

namespace uWS {

class Server : public Agent<true>
{
    friend struct Parser;
    friend class WebSocket<true>;
    // uWS:: required here because of bug in gcc: https://gcc.gnu.org/bugzilla/show_bug.cgi?id=52625
    template <bool IsServer> friend class uWS::Agent;
    friend class HTTPSocket;
private:
    uv_poll_t *listenPoll = nullptr;
    static void acceptHandler(uv_poll_t *p, int status, int events);
    static void upgradeHandler(Server *server);

    std::function<void(uv_os_sock_t, const char *, void *, const char *, size_t)> upgradeCallback;

    char *upgradeBuffer;

    char *upgradeResponse;
    uv_async_t upgradeAsync;

    // accept poll
    sockaddr_in listenAddr;
    int port;

    struct UpgradeRequest {
        uv_os_sock_t fd;
        std::string secKey;
        void *ssl;
        std::string extensions;
    };

    // upgrade queue
    std::queue<UpgradeRequest> upgradeQueue;
    std::mutex upgradeQueueMutex;

public:
    Server(int port = 0, bool master = true, unsigned int options = 0, unsigned int maxPayload = 1048576, SSLContext sslContext = SSLContext());
    ~Server();
    Server(const Server &server) = delete;
    Server &operator=(const Server &server) = delete;
    void onUpgrade(std::function<void(uv_os_sock_t, const char *, void *, const char *, size_t)> upgradeCallback);
    void upgrade(uv_os_sock_t fd, const char *secKey, void *ssl = nullptr, const char *extensions = nullptr, size_t extensionsLength = 0);
};

}

#endif // SERVER_H
