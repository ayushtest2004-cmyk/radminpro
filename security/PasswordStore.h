#pragma once
//
// PasswordStore.h - Argon2id password hashing.
//
// The server NEVER stores or transmits a plaintext password. It stores only an
// Argon2id encoded string of the form:
//
//   $argon2id$v=19$m=65536,t=3,p=1$<base64 salt>$<base64 hash>
//
// The salt is random per password and embedded in the encoded string, so each
// stored credential is unique even for identical passwords.
//
#include <cstdint>
#include <string>

namespace rp {

class PasswordStore {
public:
    // Argon2id cost parameters. Defaults follow OWASP guidance (>= 19 MiB,
    // here 64 MiB) tuned for an interactive server login.
    struct Params {
        uint32_t timeCost    = 3;      // iterations
        uint32_t memoryKiB   = 65536;  // 64 MiB
        uint32_t parallelism = 1;      // lanes/threads
        uint32_t saltLen     = 16;
        uint32_t hashLen     = 32;
    };

    // Hash `password` and return the self-describing encoded string. Throws
    // std::runtime_error on failure. The input string is securely wiped.
    static std::string hash(std::string password, const Params& p = {});

    // Constant-time verification against a stored encoded string. `password`
    // is securely wiped before return. Returns false on any error/mismatch.
    static bool verify(std::string password, const std::string& encoded);

    // True if the encoded string parses as a supported Argon2id hash.
    static bool isValidEncoded(const std::string& encoded);
};

} // namespace rp
