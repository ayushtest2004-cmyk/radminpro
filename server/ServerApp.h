#pragma once
//
// ServerApp.h - server orchestration (the "host" side).
//
// Wires the modules together: subnet pre-filter -> TLS -> Argon2 auth ->
// on-screen overlay + DXGI video stream + audited, hash-verified file transfer.
// All policy decisions defer to SecurityManager; all actions are audited.
//
#include "audit/AuditLogger.h"
#include "net/SocketTransport.h"
#include "security/SecurityManager.h"

#include <atomic>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace rp {

struct ServerConfig {
    std::string bindAddr = "0.0.0.0";
    uint16_t port = 4899;
    uint32_t monitor = 0;
    std::string allowSubnets;             // CIDR list, comma/space separated
    std::string tlsCert = "server.crt";
    std::string tlsKey = "server.key";
    std::string clientCa;                 // optional, enables mutual TLS
    std::string auditCsv = "radminpro_audit.csv";
    std::string fileRoot = "fileshare";   // sandbox root for file transfer
    uint32_t maxSessions = 8;             // concurrent session cap
    std::vector<UserRecord> users;

    // Parse "key=value" lines (see config/server.config.example).
    static ServerConfig parse(const std::string& text);
};

class ServerApp {
public:
    explicit ServerApp(ServerConfig cfg);

    // Build security/audit, bind, and run the accept loop. Blocks. Returns an
    // exit code.
    int run();

    // Cleanly stop the accept loop from another thread (closes the listener
    // socket so the blocked accept() returns immediately).
    void stop();

    // Serialize the current config back to plaintext key=value form (for the
    // GUI to re-seal after Options/Users edits).
    static std::string serialize(const ServerConfig& cfg);

private:
    void session(std::unique_ptr<SocketTransport> t, PeerInfo peer);

    ServerConfig cfg_;
    std::shared_ptr<TlsContext> tls_;
    std::shared_ptr<SecurityManager> sec_;
    std::unique_ptr<AuditLogger> audit_;
    TcpListener listener_;
    std::atomic<bool> running_{true};
    std::atomic<uint32_t> activeSessions_{0};
};

} // namespace rp
