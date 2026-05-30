#pragma once
//
// TlsContext.h - OpenSSL TLS configuration (the "data in transit" control).
//
//  * Minimum protocol TLS 1.2, maximum (preferred) TLS 1.3.
//  * SSLv2/SSLv3/TLS1.0/TLS1.1 and TLS compression are hard-disabled.
//  * AEAD-only cipher policy.
//  * For self-signed LAN deployments the client pins the server certificate by
//    SHA-256 fingerprint; for managed PKI it can verify against a CA bundle.
//
// This object owns a configured SSL_CTX. Per-connection SSL objects and the
// handshake itself live in net/SocketTransport.
//
#include <memory>
#include <string>

using SSL_CTX = struct ssl_ctx_st;
using SSL = struct ssl_st;

namespace rp {

// Render the current OpenSSL error stack as a single string (and clear it).
std::string opensslErrorString();

class TlsContext {
public:
    struct ServerConfig {
        std::string certPath; // PEM cert (chain allowed)
        std::string keyPath;  // PEM private key
        std::string clientCaPath; // optional: enable mutual-TLS by verifying clients
    };
    struct ClientConfig {
        std::string caPath;          // optional CA bundle for PKI verification
        std::string pinnedSha256Hex; // optional leaf-cert fingerprint to pin
        bool requireVerification = true; // if false (NOT recommended) accept any cert
    };

    ~TlsContext();
    TlsContext(const TlsContext&) = delete;
    TlsContext& operator=(const TlsContext&) = delete;

    static std::unique_ptr<TlsContext> makeServer(const ServerConfig& cfg);
    static std::unique_ptr<TlsContext> makeClient(const ClientConfig& cfg);

    SSL_CTX* raw() const { return ctx_; }
    bool isServer() const { return server_; }

    // Post-handshake leaf-certificate pin check (client side). Returns true if
    // no pin is configured, or if the peer cert SHA-256 matches the pin.
    bool checkPeerPin(SSL* ssl) const;

    const std::string& pinnedSha256Hex() const { return pinnedFp_; }

private:
    TlsContext(SSL_CTX* ctx, bool server) : ctx_(ctx), server_(server) {}
    SSL_CTX* ctx_ = nullptr;
    bool server_ = false;
    std::string pinnedFp_; // normalized lowercase hex, no separators
};

} // namespace rp
