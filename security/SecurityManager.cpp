#include "security/SecurityManager.h"

#include "common/Logger.h"
#include "common/Util.h"
#include "security/PasswordStore.h"

namespace rp {

SecurityManager::SecurityManager(std::shared_ptr<TlsContext> tls, SubnetFilter filter,
                                 Policy policy)
    : tls_(std::move(tls)), filter_(std::move(filter)), policy_(policy) {
    // Precompute a throwaway hash so authenticate() performs the same expensive
    // Argon2 work whether or not the username exists (anti-enumeration).
    decoyHash_ = PasswordStore::hash(toHex(randomBytes(16)));
}

void SecurityManager::addUser(UserRecord rec) {
    std::lock_guard<std::mutex> lk(mu_);
    users_[rec.username] = std::move(rec);
}

size_t SecurityManager::userCount() const {
    std::lock_guard<std::mutex> lk(mu_);
    return users_.size();
}

bool SecurityManager::isPeerAllowed(const std::string& ip) const {
    return filter_.isAllowed(ip);
}

bool SecurityManager::isLocked(const std::string& user,
                               std::chrono::steady_clock::time_point now) {
    auto it = lockouts_.find(user);
    if (it == lockouts_.end()) return false;
    auto& lk = it->second;
    if (lk.lockedUntil > now) return true;
    // Expire stale failure windows.
    if (now - lk.firstFailure > policy_.lockoutWindow) {
        lk.failures = 0;
    }
    return false;
}

void SecurityManager::recordFailure(const std::string& user,
                                    std::chrono::steady_clock::time_point now) {
    auto& lk = lockouts_[user];
    if (lk.failures == 0 || now - lk.firstFailure > policy_.lockoutWindow) {
        lk.firstFailure = now;
        lk.failures = 0;
    }
    ++lk.failures;
    if (lk.failures >= policy_.maxFailedAttempts) {
        lk.lockedUntil = now + policy_.lockoutDuration;
        RP_LOG_WARN("account locked due to repeated auth failures: " + user);
    }
}

void SecurityManager::recordSuccess(const std::string& user) {
    lockouts_.erase(user);
}

AuthOutcome SecurityManager::authenticate(const std::string& username,
                                          std::string password,
                                          const std::string& peerIp) {
    const auto now = std::chrono::steady_clock::now();

    std::string hashToCheck;
    bool known = false;
    uint32_t rights = R_None;
    {
        std::lock_guard<std::mutex> lk(mu_);
        if (isLocked(username, now)) {
            secureZero(password);
            RP_LOG_WARN("auth attempt on locked account '" + username + "' from " + peerIp);
            return {AuthStatus::LockedOut, R_None};
        }
        auto it = users_.find(username);
        if (it != users_.end()) {
            known = true;
            hashToCheck = it->second.argon2Hash;
            rights = it->second.rights;
        } else {
            hashToCheck = decoyHash_; // constant-work path (local)
        }
    }

    // Argon2id verify runs OUTSIDE the lock (it is CPU/memory heavy). For an
    // unknown user we still verify against a decoy hash so timing does not leak
    // whether the username exists. verify() wipes `password`.
    const bool passOk = PasswordStore::verify(std::move(password), hashToCheck);
    const bool ok = known && passOk;

    std::lock_guard<std::mutex> lk(mu_);
    if (ok) {
        recordSuccess(username);
        return {AuthStatus::Ok, rights};
    }
    recordFailure(username, now);
    return {AuthStatus::BadCredentials, R_None};
}

} // namespace rp
