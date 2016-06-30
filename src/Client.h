#ifndef CLIENT_H
#define CLIENT_H

#include <mutex>
#include <queue>
#include <string>
#include <functional>
#include <uv.h>

#include "Agent.h"

namespace uWS {

class Client : public Agent<false>
{
    friend struct Parser;
    friend class WebSocket<false>;
    // uWS:: required here because of bug in gcc: https://gcc.gnu.org/bugzilla/show_bug.cgi?id=52625
    template <bool IsServer> friend class uWS::Agent;
private:
    std::function<void()> connectionFailureCallback;

public:
    Client(bool master = true, int options = 0, int maxPayload = 1048576);
    ~Client();
    Client(const Client &client) = delete;
    Client &operator=(const Client &client) = delete;
    void onConnectionFailure(std::function<void()> connectionCallback);
    void connect(std::string url);
};

}

#endif // CLIENT_H
