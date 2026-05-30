#pragma once
//
// SocketTransport.h - WinSock2 + OpenSSL transport.
//
// Provides a TCP listener/connector and a framed, TLS-encrypted message stream.
// WinSock types are kept out of this header (socket_t = uintptr_t) so callers
// don't inherit <winsock2.h> include-ordering constraints.
//
#include "common/Protocol.h"
#include "security/TlsContext.h"

#include <cstdint>
#include <memory>
#include <mutex>
#include <string>

namespace rp {

using socket_t = uintptr_t;
constexpr socket_t kInvalidSocket = ~static_cast<uintptr_t>(0);

// Idempotent WSAStartup. Safe to call from anywhere; auto-cleanup at exit.
void ensureWinsock();

struct PeerInfo {
    std::string ip;
    uint16_t port = 0;
    std::string toString() const { return ip + ":" + std::to_string(port); }
};

class TcpListener {
public:
    TcpListener() = default;
    ~TcpListener();
    TcpListener(const TcpListener&) = delete;
    TcpListener& operator=(const TcpListener&) = delete;

    bool listen(const std::string& bindAddr, uint16_t port, int backlog = 16);
    // Blocking accept. Returns kInvalidSocket on error; fills `peer`.
    socket_t accept(PeerInfo& peer);
    void close();

private:
    socket_t fd_ = kInvalidSocket;
};

socket_t tcpConnect(const std::string& host, uint16_t port, int timeoutMs = 5000);

// Close a raw socket that has not been wrapped in a SocketTransport.
void closeSocket(socket_t fd);

// TLS-wrapped, length-prefixed message channel over a connected socket.
class SocketTransport {
public:
    ~SocketTransport();
    SocketTransport(const SocketTransport&) = delete;
    SocketTransport& operator=(const SocketTransport&) = delete;

    // Take ownership of an accepted/connected socket and bind it to a new SSL
    // object from `ctx`. Does NOT perform the handshake yet.
    static std::unique_ptr<SocketTransport> wrap(socket_t fd, TlsContext& ctx,
                                                 PeerInfo peer);

    // Perform SSL_accept (server) or SSL_connect (client). On the client the
    // certificate pin (if configured) is enforced here. Returns false on error.
    bool handshake();

    bool writeMessage(Op op, const Bytes& payload);
    // Blocking read of one full frame. Returns false on clean close or error.
    bool readMessage(Message& out);

    enum class ReadResult { Ok, Timeout, Closed };
    // Wait up to timeoutMs for a frame. Lets a single session thread both push
    // video and service client input without concurrent use of one SSL object.
    ReadResult readMessageTimed(Message& out, int timeoutMs);

    void close();

    // Set SO_RCVTIMEO on the underlying socket (0 = block indefinitely). Used to
    // bound the pre-session handshake/auth phase against slow-loris clients.
    void setRecvTimeoutMs(int ms);

    const PeerInfo& peer() const { return peer_; }
    std::string tlsVersion() const; // e.g. "TLSv1.3" (post-handshake)

private:
    SocketTransport(socket_t fd, TlsContext& ctx, PeerInfo peer);
    bool writeAll(const uint8_t* p, size_t n);
    bool readAll(uint8_t* p, size_t n);

    socket_t fd_;
    TlsContext& ctx_;
    SSL* ssl_ = nullptr;
    PeerInfo peer_;
    std::mutex writeMu_; // serializes writeMessage; reads stay single-reader
};

} // namespace rp
