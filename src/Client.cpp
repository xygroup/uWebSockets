#include "Client.h"
#include "Base64.h"
#include "HTTPSocket.h"
#include "WebSocket.h"
#include "Extensions.h"
#include "Parser.h"

#include <cstring>
#include <openssl/sha.h>
#include <openssl/ssl.h>
#include <vector>

void base64(unsigned char *src, char *dst)
{
    static const char *b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    for (int i = 0; i < 18; i += 3) {
        *dst++ = b64[(src[i] >> 2) & 63];
        *dst++ = b64[((src[i] & 3) << 4) | ((src[i + 1] & 240) >> 4)];
        *dst++ = b64[((src[i + 1] & 15) << 2) | ((src[i + 2] & 192) >> 6)];
        *dst++ = b64[src[i + 2] & 63];
    }
    *dst++ = b64[(src[18] >> 2) & 63];
    *dst++ = b64[((src[18] & 3) << 4) | ((src[19] & 240) >> 4)];
    *dst++ = b64[((src[19] & 15) << 2)];
    *dst++ = '=';
}

namespace uWS {

bool firstClient = true;
Client::Client(bool master, int options, int maxPayload) : Agent<false>(master, options, maxPayload)
{
    if (firstClient) {
        srand(time(nullptr));
        firstClient = false;
    }

    loop = master ? uv_default_loop() : uv_loop_new();

    onConnection([](ClientSocket socket) {});
    onConnectionFailure([]() {});
    onDisconnection([](ClientSocket socket, int code, char *message, size_t length) {});
    onMessage([](ClientSocket socket, const char *data, size_t length, OpCode opCode) {});
    onPing([](ClientSocket webSocket, char *message, size_t length) {});
    onPong([](ClientSocket socket, char *message, size_t length) {});

    recvBuffer = new char[LARGE_BUFFER_SIZE + Parser::CONSUME_POST_PADDING];
    inflateBuffer = new char[LARGE_BUFFER_SIZE];
    sendBuffer = new char[SHORT_BUFFER_SIZE];

    if (!master) {
        closeAsync.data = this;

        uv_async_init(loop, &closeAsync, [](uv_async_t *a) {
            closeHandler((Client *) a->data);
        });
    }
}

Client::~Client()
{
    delete [] (uint32_t *) recvBuffer;
    delete [] sendBuffer;
    delete [] inflateBuffer;

    if (!master) {
        uv_loop_delete((uv_loop_t *) loop);
    }
}

struct ConnectData {
    std::string protocol, host, path;
    int port;
    Client *client;

    ConnectData(Client *client, const std::string &protocol, const std::string &host, int port, const std::string &path)
        : client(client), protocol(protocol), host(host), port(port), path(path)
    {
    };
};

// move this into Parser.cpp
struct ClientHTTPData {
    // concat header here
    std::string headerBuffer;
    std::string responseKey;
    // store pointers to segments in the buffer
    std::vector<std::pair<char *, size_t>> headers;
    //reference to the receive buffer
    Client *client;

    ClientHTTPData(Client *client, const std::string &responseKey) : client(client), responseKey(responseKey) {}
};

// Tcp connect handler
const std::string HTTP_NEWLINE = "\r\n";
const std::string HTTP_END_MESSAGE = "\r\n\r\n";
void Client::connect(std::string url)
{
    std::string protocol = "ws", host, portStr, path;
    int port;
    // Parse url parts
    int pos = 0;
    int idx;
    if ((idx = url.find("://")) != std::string::npos) {
        protocol = url.substr(0, idx);
        pos = idx + 3;
    }
    if (protocol != "ws")// && protocol != "wss")
    {
        connectionFailureCallback();
        return;
    }

    int portIdx = url.find(":", pos);
    int pathIdx = url.find("/", pos);
    int queryIdx = url.find("?", pos);
    int fragmentIdx = url.find("#", pos);

    int endIdx = url.length();
    if (pathIdx != std::string::npos)
        endIdx = pathIdx;
    else if (queryIdx != std::string::npos)
        endIdx = queryIdx;
    else if (fragmentIdx != std::string::npos)
        endIdx = fragmentIdx;

    if (portIdx != std::string::npos) {
        host = url.substr(pos, portIdx - pos);
        portStr = url.substr(portIdx + 1, endIdx - portIdx - 1);
        port = std::stoi(portStr);
    }
    else {
        host = url.substr(pos, endIdx - pos);
        // Use default port values
        if (protocol == "ws")
            port = 80;
        else
            port = 443;
    }

    if (endIdx != url.length()) {
        path = url.substr(endIdx);
        // Remove any initial '/' from path
        if (path[0] == '/')
            path = path.substr(1);
    }

    auto data = new ConnectData(this, protocol, host, port, path);
    struct sockaddr_in dest = { 0 };
    dest.sin_family = AF_INET;
    dest.sin_port = htons(port);
    inet_aton(data->host.c_str(), &(dest.sin_addr));

    uv_os_fd_t fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
    {
        delete data;
        connectionFailureCallback();
        return;
    }

    uv_poll_t *connectHandle = new uv_poll_t;
    connectHandle->data = data;
    uv_poll_init_socket((uv_loop_t *) loop, connectHandle, fd);
    uv_poll_start(connectHandle, UV_WRITABLE, [](uv_poll_t *p, int status, int events) {
        uv_os_fd_t fd;
        uv_fileno((uv_handle_t *) p, (uv_os_fd_t *) &fd);
        ConnectData *cd = (ConnectData *) p->data;
        Client *client = cd->client;
        uv_poll_stop(p);

        // Generate random bytes as websocket key
        static const char palette[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        // We are generating the base64 string directly, so 16 bytes = 24 bytes in base 64
        char key [24];
        for (size_t i = 0; i < 21; ++i) {
            key[i] = palette[rand() % 64];
        }
        // Last char can only have first 2 bits set
        key[21] = palette[(rand() % 64) | 0x30];
        // Need 2 padding chars so that numChars * 6 is divisble by 8
        key[22] = key[23] = '=';

        // Construct message
        std::string msg = "GET /" + cd->path + " HTTP/1.1" + HTTP_NEWLINE +
            "Upgrade: websocket" + HTTP_NEWLINE +
            "Connection: Upgrade" + HTTP_NEWLINE +
            "Host: " + cd->host + ":" + std::to_string(cd->port) + HTTP_NEWLINE +
            "Sec-WebSocket-Key: " + std::string(key, 24) + HTTP_NEWLINE +
            "Sec-WebSocket-Version: 13" + HTTP_END_MESSAGE;
        //cout << "First message: " << msg << endl;

        // compute expected sha1 response key
        unsigned char shaInput[] = "XXXXXXXXXXXXXXXXXXXXXXXX258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
        memcpy(shaInput, key, 24);
        unsigned char shaDigest[SHA_DIGEST_LENGTH];
        SHA1(shaInput, sizeof(shaInput) - 1, shaDigest);
        char base64ShaDigest[28];
        base64(shaDigest, base64ShaDigest);
    
        p->data = new ClientHTTPData(client, std::string(base64ShaDigest, 28));
        uv_poll_start(p, UV_READABLE, [](uv_poll_t *p, int status, int events) {
            if (status < 0) {
                // error read
            }

            uv_os_fd_t fd;
            uv_fileno((uv_handle_t *) p, (uv_os_fd_t *) &fd);
            ClientHTTPData *httpData = (ClientHTTPData *) p->data;
            Client* client = httpData->client;
            int length = recv(fd, httpData->client->recvBuffer, LARGE_BUFFER_SIZE + Parser::CONSUME_POST_PADDING, 0);
            httpData->headerBuffer.append(httpData->client->recvBuffer, length);

            // did we read the complete header?
            int headerPos = httpData->headerBuffer.find(HTTP_END_MESSAGE);
            if (headerPos != std::string::npos) {
                // our part is done here
                uv_poll_stop(p);

                // Validate response
                Request h = (char *) httpData->headerBuffer.data();

                // Check response code
                if (atoi(h.value.first) != 101)
                {
                    client->connectionFailureCallback();
                    delete httpData;
                    return;
                }

                // Check that returned sha key matches expected value
                for (h++; h.key.second; h++) {
                    if (h.key.second == 20) {
                        // lowercase the key
                        for (size_t i = 0; i < h.key.second; i++) {
                            h.key.first[i] = tolower(h.key.first[i]);
                        }
                        if (!strncmp(h.key.first, "sec-websocket-accept", h.key.second)) {
                            if (strncmp(h.value.first, httpData->responseKey.c_str(), httpData->responseKey.length()))
                            {
                                client->connectionFailureCallback();
                                delete httpData;
                                return;
                            }
                            break;
                        }
                    }
                }

                // We've received a valid response, so upgrade to websocket
                uv_poll_t *clientPoll = new uv_poll_t;
                WebSocket<false> webSocket(clientPoll);
                webSocket.initPoll(client, fd, nullptr, nullptr);

                if (client->clients) {
                    webSocket.link(client->clients);
                }
                client->clients = clientPoll;
                client->connectionCallback(webSocket);

                // If we received more bytes after the end of http response, process it as a websocket message
                int spillLength = httpData->headerBuffer.length() - (headerPos + HTTP_END_MESSAGE.length());
                if (spillLength) {
                    SocketData<false> *socketData = (SocketData<false> *) webSocket.p->data;
                    char *src = socketData->agent->recvBuffer;
                    memcpy(src, httpData->headerBuffer.c_str() + (headerPos + HTTP_END_MESSAGE.length()), spillLength);
                    Parser::consume(spillLength, src, socketData, clientPoll);
                }
                delete httpData;
            } else {
                // todo: start timer to time out the connection!
            }
        });

        // Actually write the message
        int nWrite = write(fd, msg.c_str(), msg.length());
        if (nWrite < 0) 
            client->connectionFailureCallback();
    });

    if (::connect(fd, (struct sockaddr *) &dest, sizeof(dest)) < 0 && errno != EINPROGRESS)
        connectionFailureCallback();
}

void Client::onConnectionFailure(std::function<void()> connectionFailureCallback)
{
    this->connectionFailureCallback = connectionFailureCallback;
}

}
