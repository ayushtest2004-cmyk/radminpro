#include "common/Util.h"

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>

namespace rp {

Bytes randomBytes(size_t n) {
    Bytes out(n);
    if (n == 0) return out;
    if (RAND_bytes(out.data(), static_cast<int>(n)) != 1) {
        throw std::runtime_error("CSPRNG failure (RAND_bytes)");
    }
    return out;
}

// --- SHA-256 ----------------------------------------------------------------
Sha256::Sha256() : ctx_(reinterpret_cast<evp_md_ctx_st*>(EVP_MD_CTX_new())) {
    auto* c = reinterpret_cast<EVP_MD_CTX*>(ctx_);
    if (!c || EVP_DigestInit_ex(c, EVP_sha256(), nullptr) != 1) {
        if (c) EVP_MD_CTX_free(c);
        throw std::runtime_error("EVP_DigestInit_ex(sha256) failed");
    }
}

Sha256::~Sha256() {
    if (ctx_) EVP_MD_CTX_free(reinterpret_cast<EVP_MD_CTX*>(ctx_));
}

void Sha256::update(const uint8_t* data, size_t len) {
    if (len == 0) return;
    if (EVP_DigestUpdate(reinterpret_cast<EVP_MD_CTX*>(ctx_), data, len) != 1) {
        throw std::runtime_error("EVP_DigestUpdate failed");
    }
}

Hash256 Sha256::finish() {
    Hash256 out{};
    unsigned int len = 0;
    if (EVP_DigestFinal_ex(reinterpret_cast<EVP_MD_CTX*>(ctx_), out.data(), &len) != 1 ||
        len != out.size()) {
        throw std::runtime_error("EVP_DigestFinal_ex failed");
    }
    return out;
}

Hash256 sha256(const uint8_t* data, size_t len) {
    Sha256 h;
    h.update(data, len);
    return h.finish();
}

Hash256 sha256(const Bytes& data) { return sha256(data.data(), data.size()); }

// --- hex --------------------------------------------------------------------
static const char* kHex = "0123456789abcdef";

std::string toHex(const uint8_t* data, size_t len) {
    std::string s;
    s.reserve(len * 2);
    for (size_t i = 0; i < len; ++i) {
        s.push_back(kHex[data[i] >> 4]);
        s.push_back(kHex[data[i] & 0x0F]);
    }
    return s;
}
std::string toHex(const Bytes& b) { return toHex(b.data(), b.size()); }
std::string toHex(const Hash256& h) { return toHex(h.data(), h.size()); }

static int hexVal(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

Bytes fromHex(const std::string& hex) {
    if (hex.size() % 2 != 0) throw DeserializeError("hex string has odd length");
    Bytes out;
    out.reserve(hex.size() / 2);
    for (size_t i = 0; i < hex.size(); i += 2) {
        int hi = hexVal(hex[i]);
        int lo = hexVal(hex[i + 1]);
        if (hi < 0 || lo < 0) throw DeserializeError("invalid hex digit");
        out.push_back(static_cast<uint8_t>((hi << 4) | lo));
    }
    return out;
}

// --- constant-time compare --------------------------------------------------
bool constantTimeEquals(const uint8_t* a, const uint8_t* b, size_t len) {
    if (len == 0) return true;
    return CRYPTO_memcmp(a, b, len) == 0;
}
bool constantTimeEquals(const Bytes& a, const Bytes& b) {
    if (a.size() != b.size()) return false; // size is not secret
    return constantTimeEquals(a.data(), b.data(), a.size());
}

// --- secure wipe ------------------------------------------------------------
void secureZero(void* p, size_t n) {
    if (p && n) OPENSSL_cleanse(p, n);
}
void secureZero(std::string& s) {
    if (!s.empty()) OPENSSL_cleanse(&s[0], s.size());
    s.clear();
}
void secureZero(Bytes& b) {
    if (!b.empty()) OPENSSL_cleanse(b.data(), b.size());
    b.clear();
}

// --- serialization ----------------------------------------------------------
void putU8(Bytes& out, uint8_t v) { out.push_back(v); }
void putU16(Bytes& out, uint16_t v) {
    out.push_back(static_cast<uint8_t>(v >> 8));
    out.push_back(static_cast<uint8_t>(v));
}
void putU32(Bytes& out, uint32_t v) {
    out.push_back(static_cast<uint8_t>(v >> 24));
    out.push_back(static_cast<uint8_t>(v >> 16));
    out.push_back(static_cast<uint8_t>(v >> 8));
    out.push_back(static_cast<uint8_t>(v));
}
void putU64(Bytes& out, uint64_t v) {
    for (int s = 56; s >= 0; s -= 8) out.push_back(static_cast<uint8_t>(v >> s));
}
void putBytes(Bytes& out, const uint8_t* p, size_t n) { out.insert(out.end(), p, p + n); }
void putBytes(Bytes& out, const Bytes& b) { putBytes(out, b.data(), b.size()); }

void putBlob(Bytes& out, const uint8_t* p, size_t n) {
    putU32(out, static_cast<uint32_t>(n));
    putBytes(out, p, n);
}
void putString(Bytes& out, const std::string& s) {
    putBlob(out, reinterpret_cast<const uint8_t*>(s.data()), s.size());
}

void ByteReader::need(size_t n) const {
    if (off_ + n > n_) throw DeserializeError("buffer underrun while parsing message");
}
uint8_t ByteReader::u8() {
    need(1);
    return p_[off_++];
}
uint16_t ByteReader::u16() {
    need(2);
    uint16_t v = (uint16_t(p_[off_]) << 8) | uint16_t(p_[off_ + 1]);
    off_ += 2;
    return v;
}
uint32_t ByteReader::u32() {
    need(4);
    uint32_t v = (uint32_t(p_[off_]) << 24) | (uint32_t(p_[off_ + 1]) << 16) |
                 (uint32_t(p_[off_ + 2]) << 8) | uint32_t(p_[off_ + 3]);
    off_ += 4;
    return v;
}
uint64_t ByteReader::u64() {
    need(8);
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i) v = (v << 8) | p_[off_ + i];
    off_ += 8;
    return v;
}
Bytes ByteReader::bytes(size_t n) {
    need(n);
    Bytes b(p_ + off_, p_ + off_ + n);
    off_ += n;
    return b;
}
Bytes ByteReader::blob() {
    uint32_t n = u32();
    return bytes(n);
}
std::string ByteReader::str() {
    Bytes b = blob();
    return std::string(b.begin(), b.end());
}

} // namespace rp
