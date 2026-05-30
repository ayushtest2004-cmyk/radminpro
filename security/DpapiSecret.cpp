#include "security/DpapiSecret.h"

#include <windows.h>
#include <wincrypt.h>
#include <dpapi.h>

#include <stdexcept>

namespace rp {

namespace {
DATA_BLOB makeBlob(const Bytes& b) {
    DATA_BLOB blob{};
    blob.cbData = static_cast<DWORD>(b.size());
    blob.pbData = const_cast<BYTE*>(b.data()); // DPAPI does not modify input
    return blob;
}

Bytes takeBlob(DATA_BLOB& blob) {
    Bytes out(blob.pbData, blob.pbData + blob.cbData);
    if (blob.pbData) {
        SecureZeroMemory(blob.pbData, blob.cbData);
        LocalFree(blob.pbData);
        blob.pbData = nullptr;
    }
    return out;
}
} // namespace

Bytes DpapiSecret::protect(const Bytes& plaintext, Scope scope, const Bytes& entropy) {
    DATA_BLOB in = makeBlob(plaintext);
    DATA_BLOB ent = makeBlob(entropy);
    DATA_BLOB out{};

    DWORD flags = CRYPTPROTECT_UI_FORBIDDEN;
    if (scope == Scope::LocalMachine) flags |= CRYPTPROTECT_LOCAL_MACHINE;

    if (!CryptProtectData(&in, L"radminpro", entropy.empty() ? nullptr : &ent,
                          nullptr, nullptr, flags, &out)) {
        throw std::runtime_error("CryptProtectData failed: " +
                                 std::to_string(GetLastError()));
    }
    return takeBlob(out);
}

Bytes DpapiSecret::unprotect(const Bytes& ciphertext, const Bytes& entropy) {
    DATA_BLOB in = makeBlob(ciphertext);
    DATA_BLOB ent = makeBlob(entropy);
    DATA_BLOB out{};

    if (!CryptUnprotectData(&in, nullptr, entropy.empty() ? nullptr : &ent,
                            nullptr, nullptr, CRYPTPROTECT_UI_FORBIDDEN, &out)) {
        throw std::runtime_error("CryptUnprotectData failed: " +
                                 std::to_string(GetLastError()));
    }
    return takeBlob(out);
}

Bytes DpapiSecret::protectString(const std::string& s, Scope scope, const Bytes& entropy) {
    Bytes pt(s.begin(), s.end());
    Bytes ct = protect(pt, scope, entropy);
    secureZero(pt);
    return ct;
}

std::string DpapiSecret::unprotectToString(const Bytes& ciphertext, const Bytes& entropy) {
    Bytes pt = unprotect(ciphertext, entropy);
    std::string s(pt.begin(), pt.end());
    secureZero(pt);
    return s;
}

} // namespace rp
