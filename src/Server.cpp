#include "Server.h"
#include "Base64.h"
#include "HTTPSocket.h"
#include "WebSocket.h"
#include "Extensions.h"
#include "Parser.h"

#include <cstring>

#ifndef NO_OPENSSL
    #include <openssl/sha.h>
    #include <openssl/ssl.h>
#else
    #include "sha1/sha1.h"
#endif

namespace uWS {

void Server::acceptHandler(uv_poll_t *p, int status, int events)
{
    if (status < 0) {
        return;
    }

    Server *server = (Server *) p->data;

    socklen_t listenAddrLength = sizeof(sockaddr_in);
    uv_os_sock_t serverFd;
    uv_fileno((uv_handle_t *) p, &serverFd);
	uv_poll_t *clientPoll = new uv_poll_t;
    uv_os_sock_t clientFd = accept(serverFd, (sockaddr *) &server->listenAddr, &listenAddrLength);
    if (uv_poll_init_socket(server->loop, clientPoll, clientFd)) {
        return;
    }

#ifdef __APPLE__
    int noSigpipe = 1;
    setsockopt(clientFd, SOL_SOCKET, SO_NOSIGPIPE, &noSigpipe, sizeof(int));
#endif

    void *ssl = nullptr;
#ifndef NO_OPENSSL
    if (server->sslContext) {
        ssl = server->sslContext.newSSL(clientFd);
        SSL_set_accept_state((SSL *) ssl);
    }
#endif

    new HTTPSocket(clientPoll, server, ssl);
}

void Server::upgradeHandler(Server *server)
{
    server->upgradeQueueMutex.lock();

    while (!server->upgradeQueue.empty()) {
        UpgradeRequest upgradeRequest = server->upgradeQueue.front();
        server->upgradeQueue.pop();

        unsigned char shaInput[] = "XXXXXXXXXXXXXXXXXXXXXXXX258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
        memcpy(shaInput, upgradeRequest.secKey.data(), 24);
#ifndef NO_OPENSSL
        unsigned char shaDigest[SHA_DIGEST_LENGTH];
        SHA1(shaInput, sizeof(shaInput) - 1, shaDigest);
#else
        unsigned char shaDigest[sha1::kSHA1Length];
        sha1::SHA1HashBytes(shaInput, sizeof(shaInput) - 1, shaDigest);
        // TODO(Erich) SHA1 can be made to run faster, since the length (60 bytes) is known ahead of time.
#endif
        memcpy(server->upgradeBuffer, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ", 97);
        base64(shaDigest, server->upgradeBuffer + 97);
        memcpy(server->upgradeBuffer + 125, "\r\n", 2);
        size_t upgradeResponseLength = 127;

        // Latin-1 µ = \xB5 but Autobahn crashes on this char
        static char stamp[] = "Server: uWebSockets\r\n\r\n";

        // Note: This could be moved into Extensions.cpp as a "decorator" if we get more complex extension support
        PerMessageDeflate *perMessageDeflate = nullptr;
        ExtensionsParser extensionsParser(upgradeRequest.extensions.c_str());
        if ((server->options & PERMESSAGE_DEFLATE) && extensionsParser.perMessageDeflate) {
            std::string response;
            perMessageDeflate = new PerMessageDeflate(extensionsParser, server->options, response);
            response.append("\r\n");
			response.append(stamp);
            memcpy(server->upgradeBuffer + 127, response.data(), response.length());
            upgradeResponseLength += response.length();
        } else {
            memcpy(server->upgradeBuffer + 127, stamp, sizeof(stamp) - 1);
            upgradeResponseLength += sizeof(stamp) - 1;
        }

        uv_poll_t *clientPoll = new uv_poll_t;
        WebSocket<true> webSocket(clientPoll);
        webSocket.initPoll(server, upgradeRequest.fd, upgradeRequest.ssl, perMessageDeflate);
        webSocket.write(server->upgradeBuffer, upgradeResponseLength, false);

        if (server->clients) {
            webSocket.link(server->clients);
        }
        server->clients = clientPoll;
        server->connectionCallback(webSocket);
    }

    server->upgradeQueueMutex.unlock();
}

#ifndef NO_OPENSSL
Server::Server(int port, bool master, unsigned int options, unsigned int maxPayload, SSLContext sslContext) : port(port), Agent(master, options, maxPayload, sslContext)
#else
Server::Server(int port, bool master, unsigned int options, unsigned int maxPayload) : Agent(master, options, maxPayload), port(port)
#endif
{
#ifdef NODEJS_WINDOWS
    options &= ~PERMESSAGE_DEFLATE;
#endif

    loop = master ? uv_default_loop() : uv_loop_new();

    recvBuffer = new char[LARGE_BUFFER_SIZE + Parser::CONSUME_POST_PADDING];
    upgradeBuffer = new char[LARGE_BUFFER_SIZE];
    inflateBuffer = new char[LARGE_BUFFER_SIZE];
    sendBuffer = new char[SHORT_BUFFER_SIZE];

    onConnection([](ServerSocket webSocket) {});
    onDisconnection([](ServerSocket webSocket, int code, char *message, size_t length) {});
    onMessage([](ServerSocket webSocket, char *message, size_t length, OpCode opCode) {});
    onPing([](ServerSocket webSocket, char *message, size_t length) {});
    onPong([](ServerSocket webSocket, char *message, size_t length) {});
    onUpgrade([this](uv_os_sock_t fd, const char *secKey, void *ssl, const char *extensions, size_t extensionsLength) {
        upgrade(fd, secKey, ssl, extensions, extensionsLength);
    });

    if (port) {
        uv_os_sock_t listenFd = socket(AF_INET, SOCK_STREAM, 0);
        listenAddr.sin_family = AF_INET;
        listenAddr.sin_addr.s_addr = INADDR_ANY;
        listenAddr.sin_port = htons(port);

        listenPoll = new uv_poll_t;
        listenPoll->data = this;

        if (bind(listenFd, (sockaddr *) &listenAddr, sizeof(sockaddr_in)) | listen(listenFd, 10)) {
            throw ERR_LISTEN;
        }

        uv_poll_init_socket(loop, listenPoll, listenFd);
        uv_poll_start(listenPoll, UV_READABLE, acceptHandler);
    }

    if (!master) {
        upgradeAsync.data = this;
        closeAsync.data = this;

        uv_async_init(loop, &closeAsync, [](uv_async_t *a) {
            closeHandler((Server *) a->data);
        });

        uv_async_init(loop, &upgradeAsync, [](uv_async_t *a) {
            upgradeHandler((Server *) a->data);
        });
    }

    // todo: move this into PerMessageDeflate class
    writeStream = {};
    if (deflateInit2(&writeStream, Z_DEFAULT_COMPRESSION, Z_DEFLATED, -15, MAX_MEM_LEVEL, Z_DEFAULT_STRATEGY) != Z_OK) {
        throw ERR_ZLIB;
    }
}

Server::~Server()
{
    delete [] recvBuffer;
    delete [] upgradeBuffer;
    delete [] sendBuffer;
    delete [] inflateBuffer;

    if (!master) {
        uv_loop_delete(loop);
    }

    // todo: move this into PerMessageDeflate class
    deflateEnd(&writeStream);
}

void Server::onUpgrade(std::function<void (uv_os_sock_t, const char *, void *, const char *, size_t)> upgradeCallback)
{
    this->upgradeCallback = upgradeCallback;
}

void Server::upgrade(uv_os_sock_t fd, const char *secKey, void *ssl, const char *extensions, size_t extensionsLength)
{
    upgradeQueueMutex.lock();
    upgradeQueue.push({fd, std::string(secKey, 24), ssl, std::string(extensions, extensionsLength)});
    upgradeQueueMutex.unlock();

    if (master) {
        upgradeHandler(this);
    } else {
        uv_async_send(&upgradeAsync);
    }
}

}
