#ifndef SOCKETDATA_H
#define SOCKETDATA_H

#include <openssl/ssl.h>

namespace uWS {

template <bool IsServer>
class Agent;

enum SendFlags {
    SND_CONTINUATION = 1,
    SND_NO_FIN = 2
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
    SSL *ssl = nullptr;
    PerMessageDeflate *pmd = nullptr;
    std::string buffer, controlBuffer;
};

}

#endif // SOCKETDATA_H
