#pragma once
//
// ClientApp.h - the operator/console side.
//
// Establishes a pinned-TLS session, authenticates, then either runs an
// interactive viewer (view / full-control) or performs file-transfer
// transactions. File operations use FileOnly mode so no video competes on the
// wire.
//
#include "common/Protocol.h"
#include "net/SocketTransport.h"
#include "security/TlsContext.h"

#include <memory>
#include <string>

namespace rp {

struct ClientConfig {
    std::string host;
    uint16_t port = 4899;
    std::string username;
    std::string password;        // wiped after auth
    std::string pinSha256Hex;    // pin the server's self-signed cert (LAN)
    std::string caPath;          // or verify against a CA bundle (PKI)
    ConnectionMode mode = ConnectionMode::ViewOnly;
};

class ClientApp {
public:
    explicit ClientApp(ClientConfig cfg);

    // TLS connect + Hello + Argon2 auth + SessionStart. Returns false on any
    // failure (logged). Wipes the password from cfg_.
    bool connectAndAuth();

    uint32_t grantedRights() const { return rights_; }

    // Interactive screen viewer (and input forwarding when control granted).
    int runViewer();

    // Transaction-based file operations (return true on verified success).
    bool uploadFile(const std::string& localPath, const std::string& remotePath);
    bool downloadFile(const std::string& remotePath, const std::string& localPath);
    bool deleteRemote(const std::string& remotePath);
    bool moveRemote(const std::string& src, const std::string& dst);

private:
    ClientConfig cfg_;
    std::shared_ptr<TlsContext> tls_;
    std::unique_ptr<SocketTransport> t_;
    uint32_t rights_ = 0;
};

} // namespace rp
