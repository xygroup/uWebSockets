#ifndef SOCKETDATA_H
#define SOCKETDATA_H

#ifndef NO_OPENSSL
    #include <openssl/ssl.h>
#endif

namespace uWS {

template <bool IsServer>
class Agent;

enum SendFlags {
    SND_CONTINUATION = 1,
    SND_NO_FIN = 2,
	SND_COMPRESSED = 64
};

enum SocketState : int {
    READ_HEAD,
    READ_MESSAGE,
    CLOSING
};

enum SocketSendState : int {
    FRAGMENT_START,
    FRAGMENT_MID
};

struct NonceElements {
    uint64_t first;
    uint64_t second;
    uint64_t counter;
};

union Nonce {
    uint8_t bytes[24];
    NonceElements elements;
};

template <bool IsServer>
struct SocketData {
    unsigned char state = READ_HEAD;
    unsigned char sendState = FRAGMENT_START;
    unsigned char fin = true;
    char opStack = -1;
    char spill[14];
    unsigned char spillLength = 0;
    OpCode opCode[2];
    unsigned int remainingBytes = 0;
    char mask[4];
    Agent<IsServer> *agent;
    struct Queue {
        struct Message {
            char *data;
            size_t length;
            Message *nextMessage = nullptr;
            void (*callback)(WebSocket<IsServer> webSockets, void *data, bool cancelled) = nullptr;
            void *callbackData = nullptr;
        };

        Message *head = nullptr, *tail = nullptr;
        void pop()
        {
            Message *nextMessage;
            if ((nextMessage = head->nextMessage)) {
                delete [] (char *) head;
                head = nextMessage;
            } else {
                delete [] (char *) head;
                head = tail = nullptr;
            }
        }

        bool empty() {return head == nullptr;}
        Message *front() {return head;}

        void push(Message *message)
        {
            if (tail) {
                tail->nextMessage = message;
                tail = message;
            } else {
                head = message;
                tail = message;
            }
        }
    };
    Queue messageQueue;
    uv_poll_t *next = nullptr, *prev = nullptr;
    void *data = nullptr;
#ifndef NO_OPENSSL
    SSL *ssl = nullptr;
#else
    void *ssl = nullptr;
    // This is the NaCl connection information.
    uint8_t publicKey[32];
    uint8_t beforenm[32];
    Nonce nonce;
#endif
    PerMessageDeflate *pmd = nullptr;
    std::string buffer, controlBuffer;
};

}

#endif // SOCKETDATA_H
