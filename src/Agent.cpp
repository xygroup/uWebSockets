#include "Agent.h"
#include "Server.h"
#include "HTTPSocket.h"
#include "WebSocket.h"
#include "Extensions.h"
#include "Parser.h"

#include <cstring>
#include <openssl/sha.h>
#include <openssl/ssl.h>

namespace uWS {

SSLContext::SSLContext(std::string certFileName, std::string keyFileName)
{
    static bool first = true;
    if (first) {
        SSL_library_init();
        atexit([]() {
            EVP_cleanup();
        });
        first = false;
    }

    sslContext = SSL_CTX_new(SSLv23_server_method());
    if (!sslContext) {
        throw ERR_SSL;
    }

    if (SSL_CTX_use_certificate_file(sslContext, certFileName.c_str(), SSL_FILETYPE_PEM) < 0) {
        throw ERR_SSL;
    } else if (SSL_CTX_use_PrivateKey_file(sslContext, keyFileName.c_str(), SSL_FILETYPE_PEM) < 0) {
        throw ERR_SSL;
    }
}

SSLContext::SSLContext(const SSLContext &other)
{
    if (other.sslContext) {
        sslContext = other.sslContext;
        sslContext->references++;
    }
}

SSLContext::~SSLContext()
{
    SSL_CTX_free(sslContext);
}

void *SSLContext::newSSL(int fd)
{
    SSL *ssl = SSL_new(sslContext);
    SSL_set_fd(ssl, fd);
	SSL_set_mode(ssl, SSL_MODE_ENABLE_PARTIAL_WRITE);
    return ssl;
}

template <bool IsServer>
void Agent<IsServer>::closeHandler(Agent<IsServer> *agent)
{
    if (!agent->master) {
        if (IsServer)
			uv_close((uv_handle_t *) &reinterpret_cast<Server*>(agent)->upgradeAsync, [](uv_handle_t *a) {});
        uv_close((uv_handle_t *) &agent->closeAsync, [](uv_handle_t *a) {});
    }

    if (IsServer) {
        Server *server = reinterpret_cast<Server*>(agent);
		if (server->listenPoll) {
			uv_os_fd_t listenFd;
			uv_fileno((uv_handle_t *) server->listenPoll, &listenFd);
			::close(listenFd);
			uv_poll_stop(server->listenPoll);
			uv_close((uv_handle_t *) server->listenPoll, [](uv_handle_t *handle) {
				delete (uv_poll_t *) handle;
			});
		}
    }

    for (WebSocket<IsServer> webSocket = agent->clients; webSocket; webSocket = webSocket.next()) {
        webSocket.close(agent->forceClose);
    }
}

template <bool IsServer>
void Agent<IsServer>::onConnection(std::function<void (WebSocket<IsServer>)> connectionCallback)
{
    this->connectionCallback = connectionCallback;
}

template <bool IsServer>
void Agent<IsServer>::onDisconnection(std::function<void (WebSocket<IsServer>, int, char *, size_t)> disconnectionCallback)
{
    this->disconnectionCallback = disconnectionCallback;
}

template <bool IsServer>
void Agent<IsServer>::onMessage(std::function<void (WebSocket<IsServer>, char *, size_t, OpCode)> messageCallback)
{
    this->messageCallback = messageCallback;
}

template <bool IsServer>
void Agent<IsServer>::onPing(std::function<void (WebSocket<IsServer>, char *, size_t)> pingCallback)
{
    this->pingCallback = pingCallback;
}

template <bool IsServer>
void Agent<IsServer>::onPong(std::function<void (WebSocket<IsServer>, char *, size_t)> pongCallback)
{
    this->pongCallback = pongCallback;
}


template <bool IsServer>
void Agent<IsServer>::close(bool force)
{
    forceClose = force;
    if (master) {
        closeHandler(this);
    } else {
        uv_async_send(&closeAsync);
    }
}

template <bool IsServer>
void Agent<IsServer>::broadcast(char *data, size_t length, OpCode opCode)
{
	PreparedMessage *preparedMessage = WebSocket<IsServer>::prepareMessage(data, length, opCode);
    for (WebSocket<IsServer> webSocket = clients; webSocket; webSocket = webSocket.next()) {
		webSocket.sendPrepared(preparedMessage);
    }
	WebSocket<IsServer>::finalizeMessage(preparedMessage);
}

template <bool IsServer>
void Agent<IsServer>::run()
{
    uv_run(loop, UV_RUN_DEFAULT);
}

}
template class uWS::Agent<true>;
template class uWS::Agent<false>;
