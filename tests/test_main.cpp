// radminpro unit tests - a tiny assertion harness (no external test framework)
// so it builds with the same vcpkg deps as the rest of the tree. Run via CTest.
//
// Covers the pure / security-critical logic: byte+hash utilities, the wire
// protocol round-trips, the rights model, the CIDR subnet filter, Argon2id
// hashing, DPAPI sealing, and audit-log hash-chain integrity.

#include "audit/AuditLogger.h"
#include "common/FrameDiff.h"
#include "common/Protocol.h"
#include "common/Util.h"
#include "security/DpapiSecret.h"
#include "security/PasswordStore.h"
#include "security/SubnetFilter.h"

#include <windows.h>

#include <filesystem>
#include <iterator>
#include <fstream>
#include <iostream>
#include <string>

namespace fs = std::filesystem;
using namespace rp;

static int g_checks = 0;
static int g_failures = 0;

#define CHECK(cond)                                                            \
    do {                                                                       \
        ++g_checks;                                                            \
        if (!(cond)) {                                                         \
            ++g_failures;                                                      \
            std::cerr << "FAIL " << __FILE__ << ":" << __LINE__ << "  " << #cond << "\n"; \
        }                                                                      \
    } while (0)

static Bytes strBytes(const std::string& s) { return Bytes(s.begin(), s.end()); }

static void testHashAndHex() {
    // Known SHA-256 vectors.
    CHECK(toHex(sha256(strBytes(""))) ==
          "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    CHECK(toHex(sha256(strBytes("abc"))) ==
          "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");

    // Streaming SHA-256 matches one-shot.
    Sha256 h;
    h.update(reinterpret_cast<const uint8_t*>("ab"), 2);
    h.update(reinterpret_cast<const uint8_t*>("c"), 1);
    CHECK(h.finish() == sha256(strBytes("abc")));

    // hex round trip.
    Bytes r = randomBytes(33);
    CHECK(fromHex(toHex(r)) == r);

    // constant-time compare.
    CHECK(constantTimeEquals(r, r));
    Bytes r2 = r;
    r2[0] ^= 0x01;
    CHECK(!constantTimeEquals(r, r2));

    // bad hex throws.
    bool threw = false;
    try { fromHex("xyz"); } catch (const DeserializeError&) { threw = true; }
    CHECK(threw);
}

static void testByteReader() {
    Bytes b;
    putU8(b, 0x12);
    putU16(b, 0x3456);
    putU32(b, 0x789abcde);
    putU64(b, 0x0102030405060708ull);
    putString(b, "hello");

    ByteReader r(b);
    CHECK(r.u8() == 0x12);
    CHECK(r.u16() == 0x3456);
    CHECK(r.u32() == 0x789abcde);
    CHECK(r.u64() == 0x0102030405060708ull);
    CHECK(r.str() == "hello");
    CHECK(r.empty());

    // underrun throws.
    bool threw = false;
    try { r.u8(); } catch (const DeserializeError&) { threw = true; }
    CHECK(threw);
}

static void testProtocolRoundTrips() {
    {
        HelloMsg m;
        m.version = 7;
        m.clientName = "viewer-01";
        auto d = HelloMsg::decode(m.encode());
        CHECK(d.version == 7 && d.clientName == "viewer-01");
    }
    {
        AuthResultMsg m;
        m.status = AuthStatus::Ok;
        m.grantedRights = R_RemoteScreenView | R_FileTransfer;
        m.sessionId = 0xdeadbeefcafef00dull;
        auto d = AuthResultMsg::decode(m.encode());
        CHECK(d.status == AuthStatus::Ok);
        CHECK(d.grantedRights == (R_RemoteScreenView | R_FileTransfer));
        CHECK(d.sessionId == 0xdeadbeefcafef00dull);
    }
    {
        FileUploadReqMsg m;
        m.remotePath = "reports/q3.xlsx";
        m.size = 123456789ull;
        m.sha256 = sha256(strBytes("payload"));
        auto d = FileUploadReqMsg::decode(m.encode());
        CHECK(d.remotePath == "reports/q3.xlsx");
        CHECK(d.size == 123456789ull);
        CHECK(d.sha256 == m.sha256); // hash bytes preserved exactly
    }
    {
        FrameInfoMsg m;
        m.sequence = 42;
        m.width = 1920;
        m.height = 1080;
        m.stride = 1920 * 4;
        m.keyframe = true;
        auto d = FrameInfoMsg::decode(m.encode());
        CHECK(d.sequence == 42 && d.width == 1920 && d.height == 1080);
        CHECK(d.stride == 1920u * 4 && d.keyframe);
    }
    {
        FileVerifyMsg m;
        m.transferId = 9;
        m.status = FileOpStatus::HashMismatch;
        auto d = FileVerifyMsg::decode(m.encode());
        CHECK(d.transferId == 9 && d.status == FileOpStatus::HashMismatch);
    }
}

static void testVideoDiff() {
    // FrameRect round-trips intact (geometry + pixel payload).
    {
        FrameRectMsg m;
        m.sequence = 5;
        m.x = 10; m.y = 20; m.w = 30; m.h = 40;
        m.pixels = randomBytes(30u * 4 * 40);
        auto d = FrameRectMsg::decode(m.encode());
        CHECK(d.sequence == 5 && d.x == 10 && d.y == 20 && d.w == 30 && d.h == 40);
        CHECK(d.pixels == m.pixels);
    }

    // Tile change detection (128px tiles over a 256x256 BGRA frame).
    const uint32_t W = 256, H = 256, S = W * 4;
    Bytes a(static_cast<size_t>(S) * H, 0);
    Bytes b = a;
    CHECK(changedTiles(a, b, W, H, S).empty()); // identical

    b[static_cast<size_t>(5) * S + 5 * 4] = 0xFF; // pixel (5,5) -> tile (0,0)
    auto r1 = changedTiles(a, b, W, H, S);
    CHECK(r1.size() == 1);
    CHECK(r1[0].x == 0 && r1[0].y == 0 && r1[0].w == 128 && r1[0].h == 128);

    b[static_cast<size_t>(200) * S + 200 * 4] = 0xFF; // pixel (200,200) -> tile (128,128)
    auto r2 = changedTiles(a, b, W, H, S);
    CHECK(r2.size() == 2);

    // Size mismatch => empty (caller promotes to keyframe).
    Bytes c(static_cast<size_t>(S) * H + 4, 0);
    CHECK(changedTiles(a, c, W, H, S).empty());
}

static void testRights() {
    CHECK(hasRight(R_AllAccess, R_Shutdown));            // wildcard
    CHECK(hasRight(R_RemoteScreenView, R_RemoteScreenView));
    CHECK(!hasRight(R_RemoteScreenView, R_RemoteScreenControl));

    uint32_t r = rightsFromStrings({"RemoteScreenView", "FileTransfer"});
    CHECK(r == (R_RemoteScreenView | R_FileTransfer));
    CHECK(rightsToString(R_None) == "None");
    CHECK(rightsToString(r).find("FileTransfer") != std::string::npos);

    // unknown names are ignored.
    CHECK(rightsFromStrings({"Nonsense"}) == R_None);
}

static void testSubnetFilter() {
    SubnetFilter f;
    CHECK(!f.isAllowed("192.168.1.1")); // empty => fail closed

    CHECK(f.addCidr("192.168.1.0/24"));
    CHECK(f.isAllowed("192.168.1.50"));
    CHECK(!f.isAllowed("192.168.2.50"));
    CHECK(!f.isAllowed("10.0.0.1"));

    CHECK(f.addCidr("10.5.5.5/32"));     // single host
    CHECK(f.isAllowed("10.5.5.5"));
    CHECK(!f.isAllowed("10.5.5.6"));

    CHECK(f.addCidr("fe80::/10"));       // IPv6 range
    CHECK(f.isAllowed("fe80::1"));
    CHECK(!f.isAllowed("fec0::1"));

    // malformed inputs rejected.
    CHECK(!f.addCidr("not-an-ip"));
    CHECK(!f.addCidr("192.168.1.0/40"));
    CHECK(!f.isAllowed("garbage"));

    SubnetFilter list;
    CHECK(list.addList("192.168.1.0/24, 10.0.0.0/8  172.16.0.0/12") == 3);
    CHECK(list.isAllowed("172.16.99.1"));
}

static void testPasswordStore() {
    std::string enc = PasswordStore::hash(std::string("S3cret-Pass!"));
    CHECK(PasswordStore::isValidEncoded(enc));
    CHECK(enc.rfind("$argon2id$", 0) == 0);
    CHECK(PasswordStore::verify(std::string("S3cret-Pass!"), enc));
    CHECK(!PasswordStore::verify(std::string("wrong"), enc));

    // Same password hashed twice => different salts => different encodings.
    std::string enc2 = PasswordStore::hash(std::string("S3cret-Pass!"));
    CHECK(enc != enc2);
    CHECK(PasswordStore::verify(std::string("S3cret-Pass!"), enc2));
}

static void testDpapi() {
    Bytes entropy = strBytes("extra-entropy");
    Bytes ct = DpapiSecret::protectString("top-secret-config",
                                           DpapiSecret::Scope::CurrentUser, entropy);
    CHECK(!ct.empty());
    CHECK(DpapiSecret::unprotectToString(ct, entropy) == "top-secret-config");

    // Wrong entropy must fail to decrypt.
    bool threw = false;
    try {
        DpapiSecret::unprotectToString(ct, strBytes("wrong-entropy"));
    } catch (const std::exception&) {
        threw = true;
    }
    CHECK(threw);
}

// Independently recompute the audit hash-chain and confirm every row matches.
static bool verifyAuditChain(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    std::string line;
    std::string prev(64, '0');
    bool first = true;
    int dataRows = 0;
    while (std::getline(in, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (line.empty()) continue;
        if (first) { first = false; continue; } // skip header
        auto pos = line.find_last_of(',');
        if (pos == std::string::npos) return false;
        std::string rowPart = line.substr(0, pos);
        std::string chainPart = line.substr(pos + 1);
        std::string expect = toHex(sha256(strBytes(prev + rowPart)));
        if (expect != chainPart) return false;
        prev = chainPart;
        ++dataRows;
    }
    return dataRows > 0;
}

static void testAuditChain() {
    fs::path tmp = fs::temp_directory_path() /
                   ("rp_audit_test_" + std::to_string(::GetCurrentProcessId()) + ".csv");
    std::error_code ec;
    fs::remove(tmp, ec);

    {
        AuditLogger log(tmp.string());
        log.connection("192.168.1.50:51000", true, "");
        log.auth("admin", "192.168.1.50:51000", true, "RemoteScreenView");
        log.fileOp(AuditAction::FileUpload, "admin", "192.168.1.50:51000",
                   "reports/x.txt", "OK", "sha256=deadbeef");
    }
    // Reopen: the chain must resume from the previous final row.
    {
        AuditLogger log(tmp.string());
        log.fileOp(AuditAction::FileDelete, "admin", "192.168.1.50:51000",
                   "reports/x.txt", "OK", "");
    }

    CHECK(verifyAuditChain(tmp.string()));

    // Tamper with a historical row -> chain verification must now fail.
    {
        std::ifstream in(tmp.string(), std::ios::binary);
        std::string content((std::istreambuf_iterator<char>(in)),
                            std::istreambuf_iterator<char>());
        in.close();
        auto p = content.find("RemoteScreenView");
        if (p != std::string::npos) content.replace(p, 4, "XXXX");
        std::ofstream out(tmp.string(), std::ios::binary | std::ios::trunc);
        out << content;
    }
    CHECK(!verifyAuditChain(tmp.string())); // tamper detected

    fs::remove(tmp, ec);
}

int main() {
    testHashAndHex();
    testByteReader();
    testProtocolRoundTrips();
    testVideoDiff();
    testRights();
    testSubnetFilter();
    testPasswordStore();
    testDpapi();
    testAuditChain();

    std::cout << (g_checks - g_failures) << "/" << g_checks << " checks passed\n";
    if (g_failures) {
        std::cerr << g_failures << " CHECK(s) FAILED\n";
        return 1;
    }
    std::cout << "ALL TESTS PASSED\n";
    return 0;
}
