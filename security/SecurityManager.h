#pragma once
//
// SecurityManager.h - the single trust-boundary orchestrator.
//
// It is the ONLY component that touches credentials, rights, the peer
// allow-list and the TLS context. The video/audit/transport modules depend on
// it but never the reverse - this is the "Security Manager separated from the
// Video Streamer" requirement made concrete.
//
#include "common/Protocol.h"
#include "security/SubnetFilter.h"
#include "security/TlsContext.h"

#include <chrono>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

namespace rp {

struct UserRecord {
    std::string username;
    std::string argon2Hash; // Argon2id encoded string ($argon2id$...)
    uint32_t rights = R_None;
};

struct AuthOutcome {
    AuthStatus status = AuthStatus::BadCredentials;
    uint32_t rights = R_None;
};

class SecurityManager {
public:
    struct Policy {
        uint32_t maxFailedAttempts = 5;                  // per username
        std::chrono::seconds lockoutWindow{300};         // failures expire after
        std::chrono::seconds lockoutDuration{300};       // stay locked this long
    };

    SecurityManager(std::shared_ptr<TlsContext> tls, SubnetFilter filter,
                    Policy policy = {});

    void addUser(UserRecord rec);
    size_t userCount() const;

    // Cheap pre-TLS gate. True if the source IP is inside the allow-list.
    bool isPeerAllowed(const std::string& ip) const;

    // Verify credentials. `password` is consumed (securely wiped). Includes
    // per-account lockout and constant-work handling for unknown users to
    // resist enumeration/guessing.
    AuthOutcome authenticate(const std::string& username, std::string password,
                             const std::string& peerIp);

    TlsContext& tls() { return *tls_; }
    const SubnetFilter& filter() const { return filter_; }

private:
    struct Lockout {
        uint32_t failures = 0;
        std::chrono::steady_clock::time_point firstFailure{};
        std::chrono::steady_clock::time_point lockedUntil{};
    };

    bool isLocked(const std::string& user, std::chrono::steady_clock::time_point now);
    void recordFailure(const std::string& user, std::chrono::steady_clock::time_point now);
    void recordSuccess(const std::string& user);

    std::shared_ptr<TlsContext> tls_;
    SubnetFilter filter_;
    Policy policy_;
    std::map<std::string, UserRecord> users_;
    std::map<std::string, Lockout> lockouts_;
    std::string decoyHash_; // for constant-work verify on unknown users
    mutable std::mutex mu_;
};

} // namespace rp
