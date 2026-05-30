#include "security/PasswordStore.h"

#include "common/Util.h"

#include <argon2.h>

#include <stdexcept>
#include <vector>

namespace rp {

std::string PasswordStore::hash(std::string password, const Params& p) {
    try {
        Bytes salt = randomBytes(p.saltLen);

        size_t encodedLen = argon2_encodedlen(
            p.timeCost, p.memoryKiB, p.parallelism, p.saltLen, p.hashLen, Argon2_id);

        std::vector<char> encoded(encodedLen, '\0');

        int rc = argon2id_hash_encoded(
            p.timeCost, p.memoryKiB, p.parallelism,
            password.data(), password.size(),
            salt.data(), salt.size(),
            p.hashLen,
            encoded.data(), encoded.size());

        secureZero(password);
        secureZero(salt);

        if (rc != ARGON2_OK) {
            throw std::runtime_error(std::string("argon2id_hash_encoded: ") +
                                     argon2_error_message(rc));
        }
        return std::string(encoded.data()); // up to first NUL
    } catch (...) {
        secureZero(password);
        throw;
    }
}

bool PasswordStore::verify(std::string password, const std::string& encoded) {
    if (encoded.empty()) {
        secureZero(password);
        return false;
    }
    // argon2id_verify performs a constant-time comparison internally.
    int rc = argon2id_verify(encoded.c_str(), password.data(), password.size());
    secureZero(password);
    return rc == ARGON2_OK;
}

bool PasswordStore::isValidEncoded(const std::string& encoded) {
    // Cheap structural check; full validation happens in verify().
    return encoded.rfind("$argon2id$", 0) == 0;
}

} // namespace rp
