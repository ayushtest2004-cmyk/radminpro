#pragma once
//
// Util.h - byte plumbing + crypto primitives shared across modules.
// Deliberately free of any policy: just SHA-256, CSPRNG, hex, and a
// bounds-checked big-endian (de)serializer used by the wire protocol.
//
#include <array>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>

struct evp_md_ctx_st; // fwd-decl of EVP_MD_CTX to keep OpenSSL out of headers

namespace rp {

using Bytes = std::vector<uint8_t>;
using Hash256 = std::array<uint8_t, 32>;

// Thrown when a buffer is too short / malformed during deserialization.
class DeserializeError : public std::runtime_error {
public:
    explicit DeserializeError(const std::string& w) : std::runtime_error(w) {}
};

// --- CSPRNG -----------------------------------------------------------------
// Cryptographically secure random bytes (OpenSSL RAND_bytes). Throws on failure
// rather than returning weak randomness.
Bytes randomBytes(size_t n);

// --- SHA-256 ----------------------------------------------------------------
Hash256 sha256(const uint8_t* data, size_t len);
Hash256 sha256(const Bytes& data);

// Streaming SHA-256 for hashing file blocks as they arrive.
class Sha256 {
public:
    Sha256();
    ~Sha256();
    Sha256(const Sha256&) = delete;
    Sha256& operator=(const Sha256&) = delete;
    void update(const uint8_t* data, size_t len);
    Hash256 finish(); // finalizes; do not reuse afterwards
private:
    evp_md_ctx_st* ctx_;
};

// --- hex --------------------------------------------------------------------
std::string toHex(const uint8_t* data, size_t len);
std::string toHex(const Bytes& b);
std::string toHex(const Hash256& h);
Bytes fromHex(const std::string& hex); // throws DeserializeError on bad input

// --- constant-time compare --------------------------------------------------
// Length-independent of content; avoids timing oracles on secret comparisons.
bool constantTimeEquals(const uint8_t* a, const uint8_t* b, size_t len);
bool constantTimeEquals(const Bytes& a, const Bytes& b);

// --- secure wipe ------------------------------------------------------------
// Overwrite memory in a way the optimizer cannot elide (OPENSSL_cleanse).
// Use on plaintext passwords / key material once they are no longer needed.
void secureZero(void* p, size_t n);
void secureZero(std::string& s);
void secureZero(Bytes& b);

// --- big-endian serialization helpers --------------------------------------
void putU8(Bytes& out, uint8_t v);
void putU16(Bytes& out, uint16_t v);
void putU32(Bytes& out, uint32_t v);
void putU64(Bytes& out, uint64_t v);
void putBytes(Bytes& out, const uint8_t* p, size_t n);
void putBytes(Bytes& out, const Bytes& b);
// length-prefixed (u32) blob/string
void putBlob(Bytes& out, const uint8_t* p, size_t n);
void putString(Bytes& out, const std::string& s);

// Bounds-checked sequential reader.
class ByteReader {
public:
    ByteReader(const uint8_t* p, size_t n) : p_(p), n_(n) {}
    explicit ByteReader(const Bytes& b) : p_(b.data()), n_(b.size()) {}

    uint8_t  u8();
    uint16_t u16();
    uint32_t u32();
    uint64_t u64();
    Bytes    bytes(size_t n);
    Bytes    blob();   // u32 length prefix
    std::string str(); // u32 length prefix, interpreted as UTF-8

    size_t remaining() const { return n_ - off_; }
    bool   empty() const { return off_ >= n_; }

private:
    void need(size_t n) const;
    const uint8_t* p_;
    size_t n_;
    size_t off_ = 0;
};

} // namespace rp
