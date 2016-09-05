#include "Network.h"
#include "WebSocket.h"
#include "Server.h"
#include "Extensions.h"
#include "SocketData.h"
#include "Parser.h"

#include <iostream>
#include <algorithm>

#ifndef NO_OPENSSL
    #include <openssl/ssl.h>
#endif

#define likely(x)       __builtin_expect((x),1)
#define unlikely(x)     __builtin_expect((x),0)

namespace uWS {

template <bool IsServer>
void WebSocket<IsServer>::send(char *message, size_t length, OpCode opCode, void (*callback)(WebSocket webSocket, void *data, bool cancelled), void *callbackData, size_t fakedLength)
{
    size_t reportedLength = length;
    if (fakedLength) {
        reportedLength = fakedLength;
    }

	// 3 extra bytes needed in case of overflow in unmask_inplace in formatMessage
    if (length <= Agent<IsServer>::SHORT_BUFFER_SIZE - (MAX_HEADER_SIZE + 3)) {
        SocketData<IsServer> *socketData = (SocketData<IsServer> *) p->data;
        char *sendBuffer = socketData->agent->sendBuffer;
        write(sendBuffer, Parser::formatMessage<IsServer>(sendBuffer, message, length, opCode, reportedLength, false), false, callback, callbackData);
    } else {
        char *buffer = new char[sizeof(typename SocketData<IsServer>::Queue::Message) + length + (MAX_HEADER_SIZE + 3)] + sizeof(typename SocketData<IsServer>::Queue::Message);
        write(buffer, Parser::formatMessage<IsServer>(buffer, message, length, opCode, reportedLength, false), true, callback, callbackData);
    }
}

template <bool IsServer>
void WebSocket<IsServer>::ping(char *message, size_t length)
{
    send(message, length, OpCode::PING);
}

template <bool IsServer>
PreparedMessage *WebSocket<IsServer>::prepareMessage(char *data, size_t length, OpCode opCode, bool compressed)
{
    PreparedMessage *preparedMessage = new PreparedMessage;
    preparedMessage->buffer = new char[sizeof(typename SocketData<IsServer>::Queue::Message) + length + (MAX_HEADER_SIZE + 3)] + sizeof(typename SocketData<IsServer>::Queue::Message);
    preparedMessage->length = Parser::formatMessage<IsServer>(preparedMessage->buffer, data, length, opCode, length, compressed);
    preparedMessage->references = 1;
    return preparedMessage;
}

template <bool IsServer>
void WebSocket<IsServer>::sendPrepared(PreparedMessage *preparedMessage)
{
    preparedMessage->references++;
    write(preparedMessage->buffer, preparedMessage->length, false, [](WebSocket<IsServer> webSocket, void *userData, bool cancelled) {
        PreparedMessage *preparedMessage = (PreparedMessage *) userData;
        if (!--preparedMessage->references) {
            delete [] (preparedMessage->buffer - sizeof(typename SocketData<IsServer>::Queue::Message));
            delete preparedMessage;
        }
    }, preparedMessage, true);
}

template <bool IsServer>
void WebSocket<IsServer>::finalizeMessage(PreparedMessage *preparedMessage)
{
    if (!--preparedMessage->references) {
        delete [] (preparedMessage->buffer - sizeof(typename SocketData<IsServer>::Queue::Message));
        delete preparedMessage;
    }
}


template <bool IsServer>
void WebSocket<IsServer>::sendFragment(char *data, size_t length, OpCode opCode, size_t remainingBytes)
{
    SocketData<IsServer> *socketData = (SocketData<IsServer> *) p->data;
    if (remainingBytes) {
        if (socketData->sendState == FRAGMENT_START) {
            send(data, length, opCode, nullptr, nullptr, length + remainingBytes);
            socketData->sendState = FRAGMENT_MID;
        } else {
            write(data, length, false);
        }
    } else {
        if (socketData->sendState == FRAGMENT_START) {
            send(data, length, opCode);
        } else {
            write(data, length, false);
            socketData->sendState = FRAGMENT_START;
        }
    }
}

template <bool IsServer>
void WebSocket<IsServer>::handleFragment(const char *fragment, size_t length, OpCode opCode, bool fin, size_t remainingBytes, bool compressed)
{
    SocketData<IsServer> *socketData = (SocketData<IsServer> *) p->data;

    // Text or binary
    if (opCode < 3) {

        // permessage-deflate
        if (compressed) {
            socketData->pmd->setInput((char *) fragment, length);
            size_t bufferSpace;
            try {
                while (!(bufferSpace = socketData->pmd->inflate(socketData->agent->inflateBuffer, Agent<IsServer>::LARGE_BUFFER_SIZE))) {
                    socketData->buffer.append(socketData->agent->inflateBuffer, Agent<IsServer>::LARGE_BUFFER_SIZE);
                }

                if (!remainingBytes && fin) {
                    unsigned char tail[4] = {0, 0, 255, 255};
                    socketData->pmd->setInput((char *) tail, 4);
                    if (!socketData->pmd->inflate(socketData->agent->inflateBuffer + Agent<IsServer>::LARGE_BUFFER_SIZE - bufferSpace, bufferSpace)) {
                        socketData->buffer.append(socketData->agent->inflateBuffer + Agent<IsServer>::LARGE_BUFFER_SIZE - bufferSpace, bufferSpace);
                        while (!(bufferSpace = socketData->pmd->inflate(socketData->agent->inflateBuffer, Agent<IsServer>::LARGE_BUFFER_SIZE))) {
                            socketData->buffer.append(socketData->agent->inflateBuffer, Agent<IsServer>::LARGE_BUFFER_SIZE);
                        }
                    }
                }
            } catch (...) {
                close(true, 1006);
                return;
            }

            fragment = socketData->agent->inflateBuffer;
            length = Agent<IsServer>::LARGE_BUFFER_SIZE - bufferSpace;
        }

        if (!remainingBytes && fin && !socketData->buffer.length()) {
			if ((socketData->agent->maxPayload && length > socketData->agent->maxPayload) || (opCode == 1 && !isValidUtf8((unsigned char *) fragment, length))) {
                close(true, 1006);
                return;
            }

            socketData->agent->messageCallback(p, (char *) fragment, length, opCode);
        } else {
			if (socketData->agent->maxPayload && length + socketData->buffer.length() > socketData->agent->maxPayload) {
                close(true, 1006);
                return;
            }

            socketData->buffer.append(fragment, length);
            if (!remainingBytes && fin) {

                // Chapter 6
                if (opCode == 1 && !isValidUtf8((unsigned char *) socketData->buffer.c_str(), socketData->buffer.length())) {
                    close(true, 1006);
                    return;
                }

                socketData->agent->messageCallback(p, (char *) socketData->buffer.c_str(), socketData->buffer.length(), opCode);
                socketData->buffer.clear();
            }
        }
    } else {
        socketData->controlBuffer.append(fragment, length);
        if (!remainingBytes && fin) {
            if (opCode == CLOSE) {
                std::tuple<unsigned short, char *, size_t> closeFrame = Parser::parseCloseFrame(socketData->controlBuffer);
                if (std::get<2>(closeFrame) == -1)
                    close(false, 1002);
                else
                    close(false, 1000);

                // leave the controlBuffer with the close frame intact
                return;
            } else {
                if (opCode == PING) {
                    send((char *) socketData->controlBuffer.c_str(), socketData->controlBuffer.length(), OpCode::PONG);
                    socketData->agent->pingCallback(p, (char *) socketData->controlBuffer.c_str(), socketData->controlBuffer.length());
                } else if (opCode == PONG) {
                    socketData->agent->pongCallback(p, (char *) socketData->controlBuffer.c_str(), socketData->controlBuffer.length());
                }
            }
            socketData->controlBuffer.clear();
        }
    }
}

template <bool IsServer>
Address WebSocket<IsServer>::getAddress()
{
    uv_os_sock_t fd;
    uv_fileno((uv_handle_t *) p, &fd);

    sockaddr_storage addr;
    socklen_t addrLength = sizeof(addr);
    getpeername(fd, (sockaddr *) &addr, &addrLength);

    static __thread char buf[INET6_ADDRSTRLEN];

    if (addr.ss_family == AF_INET) {
        sockaddr_in *ipv4 = (sockaddr_in *) &addr;
        inet_ntop(AF_INET, &ipv4->sin_addr, buf, sizeof(buf));
        return {ntohs(ipv4->sin_port), buf, "IPv4"};
    } else {
        sockaddr_in6 *ipv6 = (sockaddr_in6 *) &addr;
        inet_ntop(AF_INET6, &ipv6->sin6_addr, buf, sizeof(buf));
        return {ntohs(ipv6->sin6_port), buf, "IPv6"};
    }
}

template <bool IsServer>
void WebSocket<IsServer>::onReadable(uv_poll_t *p, int status, int events)
{
    SocketData<IsServer> *socketData = (SocketData<IsServer> *) p->data;

    // this one is not needed, read will do this!
    if (status < 0) {
        WebSocket<IsServer>(p).close(true, 1006);
        return;
    }

    char *src = socketData->agent->recvBuffer;
    memcpy(src, socketData->spill, socketData->spillLength);
    uv_os_sock_t fd;
    uv_fileno((uv_handle_t *) p, &fd);

    // this whole SSL part should be shared with HTTPSocket
    ssize_t received;
#ifndef NO_OPENSSL
    if (socketData->ssl) {
        received = SSL_read(socketData->ssl, src + socketData->spillLength, Server::LARGE_BUFFER_SIZE - socketData->spillLength);
        // do not treat SSL_ERROR_WANT_* as hang ups
        if (received < 1) {
            switch (SSL_get_error(socketData->ssl, received)) {
            case SSL_ERROR_WANT_WRITE:
            case SSL_ERROR_WANT_READ:
                return;
            }
        }
    } else {
#endif
        received = recv(fd, src + socketData->spillLength, Server::LARGE_BUFFER_SIZE - socketData->spillLength, 0);
#ifndef NO_OPENSSL
    }
#endif

    if (received == SOCKET_ERROR || received == 0) {
        // do we have a close frame in our buffer, and did we already set the state as CLOSING?
        if (socketData->state == CLOSING && socketData->controlBuffer.length()) {
            std::tuple<unsigned short, char *, size_t> closeFrame = Parser::parseCloseFrame(socketData->controlBuffer);
            if (std::get<2>(closeFrame) == -1)
                WebSocket<IsServer>(p).close(true, 1002);
            else {
                if (!std::get<0>(closeFrame)) {
                    std::get<0>(closeFrame) = 1006;
                }
                WebSocket<IsServer>(p).close(true, std::get<0>(closeFrame), std::get<1>(closeFrame), std::get<2>(closeFrame));
            }
        } else {
            WebSocket<IsServer>(p).close(true, 1006);
        }
        return;
    }

    // do not parse any data once in closing state
    if (socketData->state == CLOSING) {
        return;
    }

    // cork sends into one large package
#ifdef __linux
    int cork = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_CORK, &cork, sizeof(int));
#endif

    Parser::consume(socketData->spillLength + received, src, socketData, p);

#ifdef __linux
    cork = 0;
    setsockopt(fd, IPPROTO_TCP, TCP_CORK, &cork, sizeof(int));
#endif
}

template <bool IsServer>
void WebSocket<IsServer>::initPoll(Agent<IsServer> *agent, uv_os_sock_t fd, void *ssl, void *perMessageDeflate)
{
    uv_poll_init_socket(agent->loop, p, fd);
    SocketData<IsServer> *socketData = new SocketData<IsServer>;
    socketData->pmd = (PerMessageDeflate *) perMessageDeflate;
    socketData->agent = agent;

#ifndef NO_OPENSSL
    socketData->ssl = (SSL *) ssl;
    if (socketData->ssl) {
#ifndef NODEJS_WINDOWS
        SSL_set_fd(socketData->ssl, fd);
#endif
        SSL_set_mode(socketData->ssl, SSL_MODE_ENABLE_PARTIAL_WRITE);
    }
#endif

    p->data = socketData;
    uv_poll_start(p, UV_READABLE, onReadable);
}

template <bool IsServer>
WebSocket<IsServer>::WebSocket(uv_poll_t *p) : p(p)
{

}

template <bool IsServer>
void WebSocket<IsServer>::link(uv_poll_t *next)
{
    SocketData<IsServer> *nextData = (SocketData<IsServer> *) next->data;
    nextData->prev = p;
    SocketData<IsServer> *data = (SocketData<IsServer> *) p->data;
    data->next = next;
}

template <bool IsServer>
uv_poll_t *WebSocket<IsServer>::next()
{
    return ((SocketData<IsServer> *) p->data)->next;
}

template <bool IsServer>
WebSocket<IsServer>::operator bool()
{
    return p;
}

template <bool IsServer>
void *WebSocket<IsServer>::getData()
{
    return ((SocketData<IsServer> *) p->data)->data;
}

template <bool IsServer>
void WebSocket<IsServer>::setData(void *data)
{
    ((SocketData<IsServer> *) p->data)->data = data;
}

#ifdef NO_OPENSSL

// These functions support NaCl public key and nonce storage/manipulation.
template <bool IsServer>
uint8_t *WebSocket<IsServer>::getPublicKey()
{
    return ((SocketData<IsServer> *) p->data)->publicKey;
}

template <bool IsServer>
void WebSocket<IsServer>::setPublicKey(uint8_t *bytes)
{
    memcpy(((SocketData<IsServer> *) p->data)->publicKey, bytes, 32);
}

template <bool IsServer>
uint8_t *WebSocket<IsServer>::getBeforenm()
{
    return ((SocketData<IsServer> *) p->data)->beforenm;
}

template <bool IsServer>
void WebSocket<IsServer>::setBeforenm(uint8_t *bytes)
{
    memcpy(((SocketData<IsServer> *) p->data)->beforenm, bytes, 32);
}

template <bool IsServer>
uint8_t *WebSocket<IsServer>::getNonce(bool incrementFirst)
{
    uWS::Nonce *nonce = &(((SocketData<IsServer> *) p->data)->nonce);
    
    if (likely(incrementFirst)) {
        nonce->elements.counter++;
    }

    return nonce->bytes;
}

template <bool IsServer>
void WebSocket<IsServer>::setNonce(uint8_t *bytes)
{
    uWS::Nonce *nonce = &(((SocketData<IsServer> *) p->data)->nonce);
    
    memcpy(nonce->bytes, bytes, 24);
}

#endif

template <bool IsServer>
void WebSocket<IsServer>::close(bool force, unsigned short code, char *data, size_t length)
{
    uv_os_sock_t fd;
    uv_fileno((uv_handle_t *) p, &fd);
    SocketData<IsServer> *socketData = (SocketData<IsServer> *) p->data;

    if (socketData->state != CLOSING) {
        socketData->state = CLOSING;
        if (socketData->prev == socketData->next) {
            socketData->agent->clients = nullptr;
        } else {
            if (socketData->prev) {
                ((SocketData<IsServer> *) socketData->prev->data)->next = socketData->next;
            } else {
                socketData->agent->clients = socketData->next;
            }
            if (socketData->next) {
                ((SocketData<IsServer> *) socketData->next->data)->prev = socketData->prev;
            }
        }

        // reuse prev as timer, mark no timer set
        socketData->prev = nullptr;

        // call disconnection callback on first close (graceful or force)
        socketData->agent->disconnectionCallback(p, code, data, length);
    } else if (!force) {
        std::cerr << "WARNING: Already gracefully closed: " << p << std::endl;
        return;
    }

    if (force) {
        // delete all messages in queue
        while (!socketData->messageQueue.empty()) {
            typename SocketData<IsServer>::Queue::Message *message = socketData->messageQueue.front();
            if (message->callback) {
                message->callback(nullptr, message->callbackData, true);
            }
            socketData->messageQueue.pop();
        }

        uv_poll_stop(p);
        uv_close((uv_handle_t *) p, [](uv_handle_t *handle) {
            delete (uv_poll_t *) handle;
        });

        ::close(fd);
#ifndef NO_OPENSSL
        SSL_free(socketData->ssl);
#endif
        socketData->controlBuffer.clear();

        // cancel force close timer
        if (socketData->prev) {
            uv_timer_stop((uv_timer_t *) socketData->prev);
            uv_close((uv_handle_t *) socketData->prev, [](uv_handle_t *handle) {
                delete (uv_timer_t *) handle;
            });
        }

        delete socketData->pmd;
        delete socketData;
    } else {
        // force close after 15 seconds
        socketData->prev = (uv_poll_t *) new uv_timer_t;
        uv_timer_init(socketData->agent->loop, (uv_timer_t *) socketData->prev);
        ((uv_timer_t *) socketData->prev)->data = p;
        uv_timer_start((uv_timer_t *) socketData->prev, [](uv_timer_t *timer) {
            WebSocket((uv_poll_t *) timer->data).close(true, 1006);
        }, 15000, 0);

        char *sendBuffer = socketData->agent->sendBuffer;
        if (code) {
            length = std::min<size_t>(1024, length) + 2;
            *((uint16_t *) &sendBuffer[length + SHORT_MESSAGE_HEADER[!IsServer]]) = htons(code);
            memcpy(&sendBuffer[length + SHORT_MESSAGE_HEADER[!IsServer] + 2], data, length - 2);
        }
        write((char *) sendBuffer, Parser::formatMessage<IsServer>(sendBuffer, &sendBuffer[length + SHORT_MESSAGE_HEADER[!IsServer]], length, CLOSE, length, false), false, [](WebSocket<IsServer> webSocket, void *data, bool cancelled) {
            if (!cancelled) {
                uv_os_sock_t fd;
                uv_fileno((uv_handle_t *) webSocket.p, &fd);
#ifndef NO_OPENSSL
                SocketData<IsServer> *socketData = (SocketData<IsServer> *) webSocket.p->data;
                if (socketData->ssl) {
                    SSL_shutdown(socketData->ssl);
                }
#endif
                shutdown(fd, SHUT_WR);
            }
        });
    }
}

// async Unix send (has a Message struct in the start if transferOwnership OR preparedMessage)
template <bool IsServer>
void WebSocket<IsServer>::write(char *data, size_t length, bool transferOwnership, void(*callback)(WebSocket<IsServer> webSocket, void *data, bool cancelled), void *callbackData, bool preparedMessage)
{
    uv_os_sock_t fd;
    uv_fileno((uv_handle_t *) p, &fd);

    ssize_t sent = 0;
    SocketData<IsServer> *socketData = (SocketData<IsServer> *) p->data;
    if (!socketData->messageQueue.empty()) {
        goto queueIt;
    }

#ifndef NO_OPENSSL
    if (socketData->ssl) {
        sent = SSL_write(socketData->ssl, data, length);
    } else {
#endif
        sent = ::send(fd, data, length, MSG_NOSIGNAL);
#ifndef NO_OPENSSL
    }
#endif

    if (sent == (int) length) {
        // everything was sent in one go!
        if (transferOwnership) {
            delete [] (data - sizeof(typename SocketData<IsServer>::Queue::Message));
        }

        if (callback) {
            callback(p, callbackData, false);
        }

    } else {
        // not everything was sent
        if (sent == SOCKET_ERROR) {
            // check to see if any error occurred
#ifndef NO_OPENSSL
            if (socketData->ssl) {
                int error = SSL_get_error(socketData->ssl, sent);
                if (error == SSL_ERROR_WANT_READ || error == SSL_ERROR_WANT_WRITE) {
                    goto queueIt;
                }
            } else {
#endif
#ifdef _WIN32
                if (WSAGetLastError() == WSAENOBUFS || WSAGetLastError() == WSAEWOULDBLOCK) {
#else
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
#endif
                    goto queueIt;
                }
#ifndef NO_OPENSSL
            }
#endif

            // error sending!
            if (transferOwnership) {
                delete [] (data - sizeof(typename SocketData<IsServer>::Queue::Message));
            }

            if (callback) {
                callback(p, callbackData, true);
            }

            return;
        } else {

            queueIt:
            sent = std::max<ssize_t>(sent, 0);

            // queue the rest of the message!
            typename SocketData<IsServer>::Queue::Message *messagePtr;
            if (transferOwnership) {
                messagePtr = (typename SocketData<IsServer>::Queue::Message *) (data - sizeof(typename SocketData<IsServer>::Queue::Message));
                messagePtr->data = data + sent;
                messagePtr->length = length - sent;
                messagePtr->nextMessage = nullptr;
            } else if (preparedMessage) {
                // these allocations are always small and could belong to the same memory block
                // best would be to use a stack and delete the whole stack when the prepared message gets deleted
                messagePtr = (typename SocketData<IsServer>::Queue::Message *) new char[sizeof(typename SocketData<IsServer>::Queue::Message)];
                messagePtr->data = data + sent;
                messagePtr->length = length - sent;
                messagePtr->nextMessage = nullptr;
            } else {
                // we need to copy the buffer
                messagePtr = (typename SocketData<IsServer>::Queue::Message *) new char[sizeof(typename SocketData<IsServer>::Queue::Message) + length - sent];
                messagePtr->length = length - sent;
                messagePtr->data = ((char *) messagePtr) + sizeof(typename SocketData<IsServer>::Queue::Message);
                messagePtr->nextMessage = nullptr;
                memcpy(messagePtr->data, data + sent, messagePtr->length);
            }

            messagePtr->callback = callback;
            ((SocketData<IsServer> *) p->data)->messageQueue.push(messagePtr);

            // only start this if we just broke the 0 queue size!
            uv_poll_start(p, UV_WRITABLE | UV_READABLE, [](uv_poll_t *handle, int status, int events) {

                // handle all poll errors with forced disconnection
                if (status < 0) {
                    WebSocket<IsServer>(handle).close(true, 1006);
                    return;
                }

                // handle reads if available
                if (events & UV_READABLE) {
                    onReadable(handle, status, events);
                    if (!(events & UV_WRITABLE)) {
                        return;
                    }
                }

                SocketData<IsServer> *socketData = (SocketData<IsServer> *) handle->data;

                if (socketData->state == CLOSING) {
                    if (uv_is_closing((uv_handle_t *) handle)) {
                        return;
                    } else {
                        uv_poll_start(handle, UV_READABLE, onReadable);
                    }
                }

                uv_os_sock_t fd;
                uv_fileno((uv_handle_t *) handle, &fd);

                do {
                    typename SocketData<IsServer>::Queue::Message *messagePtr = socketData->messageQueue.front();

                    ssize_t sent;
#ifndef NO_OPENSSL
                    if (socketData->ssl) {
                        sent = SSL_write(socketData->ssl, messagePtr->data, messagePtr->length);
                    } else {
#endif
                        sent = ::send(fd, messagePtr->data, messagePtr->length, MSG_NOSIGNAL);
#ifndef NO_OPENSSL
                    }
#endif
                    if (sent == (int) messagePtr->length) {

                        if (messagePtr->callback) {
                            messagePtr->callback(handle, messagePtr->callbackData, false);
                        }

                        socketData->messageQueue.pop();
                    } else {
                        if (sent == SOCKET_ERROR) {
                            // check to see if any error occurred
#ifndef NO_OPENSSL
                            if (socketData->ssl) {
                                int error = SSL_get_error(socketData->ssl, sent);
                                if (error == SSL_ERROR_WANT_READ || error == SSL_ERROR_WANT_WRITE) {
                                    return;
                                }
                            } else {
#endif
                #ifdef _WIN32
                                if (WSAGetLastError() == WSAENOBUFS || WSAGetLastError() == WSAEWOULDBLOCK) {
                #else
                                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                #endif
                                    return;
                                }
#ifndef NO_OPENSSL
                            }
#endif
                            // error sending!
                            uv_poll_start(handle, UV_READABLE, onReadable);
                            return;
                        } else {
                            // update the Message
                            messagePtr->data += sent;
                            messagePtr->length -= sent;
                            return;
                        }
                    }
                } while (!socketData->messageQueue.empty());

                // only receive when we have fully sent everything
                uv_poll_start(handle, UV_READABLE, onReadable);
            });
        }
    }
}
template class uWS::WebSocket<true>;
template class uWS::WebSocket<false>;

}
