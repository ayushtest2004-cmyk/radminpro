#pragma once
//
// DpapiSecret.h - data-at-rest protection via Windows DPAPI.
//
// Compliance requirement: "Any passwords or configs stored on the PC must be
// encrypted (Windows DPAPI)." We use CryptProtectData so the on-disk config
// (which holds the Argon2 credential, TLS key path, allow-list, etc.) is bound
// to the machine (or user) and cannot be read by copying the file elsewhere.
//
#include "common/Util.h"

#include <string>

namespace rp {

class DpapiSecret {
public:
    enum class Scope {
        CurrentUser,  // only the same Windows user can decrypt
        LocalMachine, // any process on this machine can decrypt (use for services)
    };

    // Encrypt. `entropy` is optional secondary secret mixed into the key.
    // Throws std::runtime_error on failure.
    static Bytes protect(const Bytes& plaintext,
                         Scope scope = Scope::LocalMachine,
                         const Bytes& entropy = {});

    // Decrypt. Scope is embedded in the blob, so it is not required here;
    // `entropy` must match what was used at protect time.
    static Bytes unprotect(const Bytes& ciphertext, const Bytes& entropy = {});

    static Bytes protectString(const std::string& s,
                               Scope scope = Scope::LocalMachine,
                               const Bytes& entropy = {});
    static std::string unprotectToString(const Bytes& ciphertext,
                                          const Bytes& entropy = {});
};

} // namespace rp
