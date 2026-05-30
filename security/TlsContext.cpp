#include "security/TlsContext.h"

#include "common/Util.h"

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#include <cctype>
#include <stdexcept>

namespace rp {

std::string opensslErrorString() {
    std::string out;
    unsigned long e;
    char buf[256];
    while ((e = ERR_get_error()) != 0) {
        ERR_error_string_n(e, buf, sizeof(buf));
        if (!out.empty()) out += "; ";
        out += buf;
    }
    return out.empty() ? "(no OpenSSL error)" : out;
}

namespace {

std::string normalizeFp(const std::string& s) {
    std::string o;
    o.reserve(s.size());
    for (char c : s) {
        if (c == ':' || c == ' ' || c == '-') continue;
        o.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
    }
    return o;
}

// Apply the protocol/cipher hardening shared by client and server.
void configureCommon(SSL_CTX* ctx) {
    if (SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION) != 1 ||
        SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION) != 1) {
        throw std::runtime_error("set proto version: " + opensslErrorString());
    }

    // Belt-and-suspenders: explicitly forbid all legacy protocols + compression
    // + insecure renegotiation, and let the server choose the cipher.
    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1 |
                                 SSL_OP_NO_TLSv1_1 | SSL_OP_NO_COMPRESSION |
                                 SSL_OP_NO_RENEGOTIATION |
                                 SSL_OP_CIPHER_SERVER_PREFERENCE);

    // TLS 1.2 cipher allow-list: forward-secret AEAD only.
    if (SSL_CTX_set_cipher_list(
            ctx,
            "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:"
            "ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:"
            "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256") != 1) {
        throw std::runtime_error("set_cipher_list: " + opensslErrorString());
    }
    // TLS 1.3 suites.
    if (SSL_CTX_set_ciphersuites(ctx,
                                 "TLS_AES_256_GCM_SHA384:"
                                 "TLS_CHACHA20_POLY1305_SHA256:"
                                 "TLS_AES_128_GCM_SHA256") != 1) {
        throw std::runtime_error("set_ciphersuites: " + opensslErrorString());
    }

    SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);
}

struct CtxGuard {
    SSL_CTX* p;
    ~CtxGuard() { if (p) SSL_CTX_free(p); }
    SSL_CTX* release() { SSL_CTX* t = p; p = nullptr; return t; }
};

} // namespace

TlsContext::~TlsContext() {
    if (ctx_) SSL_CTX_free(ctx_);
}

std::unique_ptr<TlsContext> TlsContext::makeServer(const ServerConfig& cfg) {
    CtxGuard g{SSL_CTX_new(TLS_server_method())};
    if (!g.p) throw std::runtime_error("SSL_CTX_new(server): " + opensslErrorString());
    configureCommon(g.p);

    if (SSL_CTX_use_certificate_chain_file(g.p, cfg.certPath.c_str()) != 1) {
        throw std::runtime_error("load cert '" + cfg.certPath + "': " + opensslErrorString());
    }
    if (SSL_CTX_use_PrivateKey_file(g.p, cfg.keyPath.c_str(), SSL_FILETYPE_PEM) != 1) {
        throw std::runtime_error("load key '" + cfg.keyPath + "': " + opensslErrorString());
    }
    if (SSL_CTX_check_private_key(g.p) != 1) {
        throw std::runtime_error("cert/key mismatch: " + opensslErrorString());
    }

    // Optional mutual TLS: verify client certificates against the given CA.
    if (!cfg.clientCaPath.empty()) {
        if (SSL_CTX_load_verify_locations(g.p, cfg.clientCaPath.c_str(), nullptr) != 1) {
            throw std::runtime_error("load client CA: " + opensslErrorString());
        }
        SSL_CTX_set_verify(g.p, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, nullptr);
    }

    return std::unique_ptr<TlsContext>(new TlsContext(g.release(), /*server=*/true));
}

std::unique_ptr<TlsContext> TlsContext::makeClient(const ClientConfig& cfg) {
    CtxGuard g{SSL_CTX_new(TLS_client_method())};
    if (!g.p) throw std::runtime_error("SSL_CTX_new(client): " + opensslErrorString());
    configureCommon(g.p);

    const std::string pin = normalizeFp(cfg.pinnedSha256Hex);

    if (!cfg.caPath.empty()) {
        // Managed-PKI mode: standard chain verification.
        if (SSL_CTX_load_verify_locations(g.p, cfg.caPath.c_str(), nullptr) != 1) {
            throw std::runtime_error("load CA '" + cfg.caPath + "': " + opensslErrorString());
        }
        SSL_CTX_set_verify(g.p, SSL_VERIFY_PEER, nullptr);
    } else if (!pin.empty()) {
        // Self-signed LAN mode: chain verification is meaningless, so we rely on
        // a post-handshake fingerprint pin (enforced in checkPeerPin()).
        SSL_CTX_set_verify(g.p, SSL_VERIFY_NONE, nullptr);
    } else if (cfg.requireVerification) {
        throw std::runtime_error(
            "client TLS misconfigured: provide either caPath or pinnedSha256Hex "
            "(or explicitly set requireVerification=false, which is insecure)");
    } else {
        SSL_CTX_set_verify(g.p, SSL_VERIFY_NONE, nullptr); // INSECURE, opt-in only
    }

    auto ctx = std::unique_ptr<TlsContext>(new TlsContext(g.release(), /*server=*/false));
    ctx->pinnedFp_ = pin;
    return ctx;
}

bool TlsContext::checkPeerPin(SSL* ssl) const {
    if (pinnedFp_.empty()) return true; // no pin configured -> nothing to enforce

    X509* cert = SSL_get1_peer_certificate(ssl);
    if (!cert) return false;

    unsigned char* der = nullptr;
    int len = i2d_X509(cert, &der);
    bool ok = false;
    if (len > 0 && der) {
        const std::string got = toHex(sha256(der, static_cast<size_t>(len)));
        // got is 64 lowercase hex chars; pinnedFp_ is normalized the same way.
        ok = (got.size() == pinnedFp_.size()) &&
             constantTimeEquals(reinterpret_cast<const uint8_t*>(got.data()),
                                reinterpret_cast<const uint8_t*>(pinnedFp_.data()),
                                got.size());
        OPENSSL_free(der);
    }
    X509_free(cert);
    return ok;
}

} // namespace rp
