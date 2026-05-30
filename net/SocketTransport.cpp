#include "net/SocketTransport.h"

#include <winsock2.h>
#include <ws2tcpip.h>

#include <openssl/err.h>
#include <openssl/ssl.h>

#include "common/Logger.h"

#include <cstdlib>
#include <cstring>
#include <mutex>
#include <stdexcept>

namespace rp {

void ensureWinsock() {
    static std::once_flag once;
    std::call_once(once, [] {
        WSADATA wsa{};
        if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
            throw std::runtime_error("WSAStartup failed");
        }
        std::atexit([] { WSACleanup(); });
    });
}

namespace {
SOCKET toSock(socket_t s) { return static_cast<SOCKET>(s); }
socket_t fromSock(SOCKET s) { return static_cast<socket_t>(s); }
} // namespace

// --------------------------------------------------------------------------
TcpListener::~TcpListener() { close(); }

bool TcpListener::listen(const std::string& bindAddr, uint16_t port, int backlog) {
    ensureWinsock();
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) return false;

    BOOL yes = TRUE;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&yes), sizeof(yes));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (bindAddr.empty() || bindAddr == "0.0.0.0") {
        addr.sin_addr.s_addr = INADDR_ANY;
    } else if (InetPtonA(AF_INET, bindAddr.c_str(), &addr.sin_addr) != 1) {
        closesocket(s);
        return false;
    }

    if (bind(s, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == SOCKET_ERROR ||
        ::listen(s, backlog) == SOCKET_ERROR) {
        RP_LOG_ERROR("bind/listen failed on port " + std::to_string(port) + " (WSA " +
                     std::to_string(WSAGetLastError()) + ")");
        closesocket(s);
        return false;
    }
    fd_ = fromSock(s);
    return true;
}

socket_t TcpListener::accept(PeerInfo& peer) {
    if (fd_ == kInvalidSocket) return kInvalidSocket;
    sockaddr_in pa{};
    int palen = sizeof(pa);
    SOCKET c = ::accept(toSock(fd_), reinterpret_cast<sockaddr*>(&pa), &palen);
    if (c == INVALID_SOCKET) return kInvalidSocket;

    char ip[INET_ADDRSTRLEN] = {};
    InetNtopA(AF_INET, &pa.sin_addr, ip, sizeof(ip));
    peer.ip = ip;
    peer.port = ntohs(pa.sin_port);
    return fromSock(c);
}

void TcpListener::close() {
    if (fd_ != kInvalidSocket) {
        closesocket(toSock(fd_));
        fd_ = kInvalidSocket;
    }
}

socket_t tcpConnect(const std::string& host, uint16_t port, int timeoutMs) {
    ensureWinsock();

    addrinfo hints{};
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    addrinfo* res = nullptr;
    if (getaddrinfo(host.c_str(), std::to_string(port).c_str(), &hints, &res) != 0 || !res) {
        return kInvalidSocket;
    }

    SOCKET s = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (s == INVALID_SOCKET) {
        freeaddrinfo(res);
        return kInvalidSocket;
    }

    // Non-blocking connect with select() so we honour timeoutMs.
    u_long nb = 1;
    ioctlsocket(s, FIONBIO, &nb);
    int rc = ::connect(s, res->ai_addr, static_cast<int>(res->ai_addrlen));
    freeaddrinfo(res);

    if (rc == SOCKET_ERROR && WSAGetLastError() == WSAEWOULDBLOCK) {
        fd_set wfds;
        FD_ZERO(&wfds);
        FD_SET(s, &wfds);
        timeval tv{timeoutMs / 1000, (timeoutMs % 1000) * 1000};
        if (select(0, nullptr, &wfds, nullptr, &tv) <= 0) {
            closesocket(s);
            return kInvalidSocket;
        }
        int err = 0;
        int len = sizeof(err);
        getsockopt(s, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&err), &len);
        if (err != 0) {
            closesocket(s);
            return kInvalidSocket;
        }
    } else if (rc == SOCKET_ERROR) {
        closesocket(s);
        return kInvalidSocket;
    }

    nb = 0; // back to blocking for the TLS layer
    ioctlsocket(s, FIONBIO, &nb);
    return fromSock(s);
}

void closeSocket(socket_t fd) {
    if (fd != kInvalidSocket) closesocket(toSock(fd));
}

void SocketTransport::setRecvTimeoutMs(int ms) {
    if (fd_ == kInvalidSocket) return;
    DWORD tv = static_cast<DWORD>(ms);
    setsockopt(toSock(fd_), SOL_SOCKET, SO_RCVTIMEO,
               reinterpret_cast<const char*>(&tv), sizeof(tv));
}

// --------------------------------------------------------------------------
SocketTransport::SocketTransport(socket_t fd, TlsContext& ctx, PeerInfo peer)
    : fd_(fd), ctx_(ctx), peer_(std::move(peer)) {}

SocketTransport::~SocketTransport() { close(); }

std::unique_ptr<SocketTransport> SocketTransport::wrap(socket_t fd, TlsContext& ctx,
                                                       PeerInfo peer) {
    auto t = std::unique_ptr<SocketTransport>(new SocketTransport(fd, ctx, std::move(peer)));
    t->ssl_ = SSL_new(ctx.raw());
    if (!t->ssl_) return nullptr;
    // Windows SOCKET handles are documented to fit in 32 bits for this purpose.
    SSL_set_fd(t->ssl_, static_cast<int>(toSock(fd)));
    return t;
}

bool SocketTransport::handshake() {
    if (!ssl_) return false;
    if (ctx_.isServer()) SSL_set_accept_state(ssl_);
    else SSL_set_connect_state(ssl_);

    for (;;) {
        int r = ctx_.isServer() ? SSL_accept(ssl_) : SSL_connect(ssl_);
        if (r == 1) break;
        int err = SSL_get_error(ssl_, r);
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) continue;
        RP_LOG_ERROR("TLS handshake with " + peer_.toString() + " failed: " +
                     opensslErrorString());
        return false;
    }

    // Client-side certificate pinning enforcement.
    if (!ctx_.isServer() && !ctx_.checkPeerPin(ssl_)) {
        RP_LOG_ERROR("server certificate pin mismatch for " + peer_.toString() +
                     " - aborting");
        return false;
    }
    RP_LOG_INFO("TLS established with " + peer_.toString() + " (" + tlsVersion() + ")");
    return true;
}

std::string SocketTransport::tlsVersion() const {
    return ssl_ ? SSL_get_version(ssl_) : "none";
}

bool SocketTransport::writeAll(const uint8_t* p, size_t n) {
    size_t off = 0;
    while (off < n) {
        int w = SSL_write(ssl_, p + off, static_cast<int>(n - off));
        if (w > 0) {
            off += static_cast<size_t>(w);
            continue;
        }
        int err = SSL_get_error(ssl_, w);
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) continue;
        return false;
    }
    return true;
}

bool SocketTransport::readAll(uint8_t* p, size_t n) {
    size_t off = 0;
    while (off < n) {
        int r = SSL_read(ssl_, p + off, static_cast<int>(n - off));
        if (r > 0) {
            off += static_cast<size_t>(r);
            continue;
        }
        int err = SSL_get_error(ssl_, r);
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) continue;
        return false; // ZERO_RETURN (clean close) or hard error
    }
    return true;
}

bool SocketTransport::writeMessage(Op op, const Bytes& payload) {
    const uint64_t total = 1ull + payload.size();
    if (total > kMaxMessageSize) {
        RP_LOG_ERROR("refusing to send oversize frame (" + std::to_string(total) + ")");
        return false;
    }
    Bytes frame;
    frame.reserve(4 + static_cast<size_t>(total));
    putU32(frame, static_cast<uint32_t>(total));
    putU8(frame, static_cast<uint8_t>(op));
    putBytes(frame, payload);
    std::lock_guard<std::mutex> lk(writeMu_);
    return writeAll(frame.data(), frame.size());
}

bool SocketTransport::readMessage(Message& out) {
    uint8_t lenBuf[4];
    if (!readAll(lenBuf, 4)) return false;
    uint32_t len = (uint32_t(lenBuf[0]) << 24) | (uint32_t(lenBuf[1]) << 16) |
                   (uint32_t(lenBuf[2]) << 8) | uint32_t(lenBuf[3]);
    if (len < 1 || len > kMaxMessageSize) {
        RP_LOG_ERROR("invalid frame length " + std::to_string(len) + " from " +
                     peer_.toString());
        return false;
    }
    Bytes body(len);
    if (!readAll(body.data(), len)) return false;
    out.op = static_cast<Op>(body[0]);
    out.payload.assign(body.begin() + 1, body.end());
    return true;
}

SocketTransport::ReadResult SocketTransport::readMessageTimed(Message& out, int timeoutMs) {
    // If OpenSSL already has buffered application data, read it immediately.
    if (ssl_ && SSL_pending(ssl_) == 0) {
        fd_set rfds;
        FD_ZERO(&rfds);
        SOCKET s = toSock(fd_);
        FD_SET(s, &rfds);
        timeval tv{timeoutMs / 1000, (timeoutMs % 1000) * 1000};
        int r = select(0, &rfds, nullptr, nullptr, &tv);
        if (r == 0) return ReadResult::Timeout;
        if (r < 0) return ReadResult::Closed;
    }
    return readMessage(out) ? ReadResult::Ok : ReadResult::Closed;
}

void SocketTransport::close() {
    if (ssl_) {
        SSL_shutdown(ssl_);
        SSL_free(ssl_);
        ssl_ = nullptr;
    }
    if (fd_ != kInvalidSocket) {
        closesocket(toSock(fd_));
        fd_ = kInvalidSocket;
    }
}

} // namespace rp
