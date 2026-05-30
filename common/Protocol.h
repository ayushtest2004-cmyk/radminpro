#pragma once
//
// Protocol.h - the wire contract between client and server.
//
// Every message travels INSIDE the TLS 1.3 tunnel as a length-prefixed frame:
//
//     [ u32 length ][ u8 opcode ][ payload ... ]   (length covers opcode+payload)
//
// This header defines opcodes, the per-user rights bitmask (mirroring the
// Radmin "Rights" grid), the connection modes (Full Control / View Only), and
// typed encode/decode for the transaction-based file transfer.
//
#include "common/Util.h"

#include <cstdint>
#include <string>

namespace rp {

constexpr uint16_t kProtocolVersion = 1;

// Hard caps to bound memory use over an untrusted-but-encrypted channel.
constexpr uint32_t kMaxMessageSize = 16u * 1024 * 1024; // 16 MiB per frame
constexpr uint32_t kFileBlockSize  = 64u * 1024;        // 64 KiB file chunks

// ---------------------------------------------------------------------------
enum class Op : uint8_t {
    Hello           = 0x01, // C->S  version, clientName
    ServerHello     = 0x02, // S->C  version, serverName
    AuthRequest     = 0x10, // C->S  username, password  (only sent post-TLS)
    AuthResult      = 0x11, // S->C  status, grantedRights, sessionId
    SessionStart    = 0x20, // C->S  requested ConnectionMode

    FrameInfo       = 0x30, // S->C  geometry + sequence + flags (keyframe)
    FrameData       = 0x31, // S->C  one chunk of a full (key)frame
    FrameEnd        = 0x32, // S->C  sequence (frame complete -> present)
    FrameRect       = 0x33, // S->C  one changed tile (delta frame)

    InputMouse      = 0x40, // C->S  (Full Control only)
    InputKey        = 0x41, // C->S  (Full Control only)

    FileUploadReq   = 0x50, // C->S  path, size, sha256
    FileDownloadReq = 0x51, // C->S  path
    FileAccept      = 0x52, // S->C  transferId [+ size + sha256 for download]
    FileReject      = 0x53, // S->C  reason
    FileBlock       = 0x54, // either transferId, seq, data
    FileComplete    = 0x55, // sender   transferId
    FileVerify      = 0x56, // receiver transferId, ok?  (hash recomputed)
    FileMove        = 0x57, // C->S  src, dst
    FileDelete      = 0x58, // C->S  path
    FileOpResult    = 0x59, // S->C  status, message

    Error           = 0x70, // either code, message
    Ping            = 0x7E,
    Bye             = 0x7F,
};

const char* opName(Op op);

// ---------------------------------------------------------------------------
// Per-user rights. Mirrors the Radmin "Rights / Allow" grid in the reference
// screenshots. AllAccess is a wildcard that satisfies every check.
enum Rights : uint32_t {
    R_None               = 0u,
    R_AllAccess          = 1u << 0,
    R_RemoteScreenView   = 1u << 1,
    R_RemoteScreenControl= 1u << 2,
    R_FileTransfer       = 1u << 3,
    R_Chat               = 1u << 4,
    R_SendMessage        = 1u << 5,
    R_Shutdown           = 1u << 6,
    R_Redirect           = 1u << 7,
    R_Telnet             = 1u << 8,
    R_VoiceChat          = 1u << 9,
};

// True if `granted` permits `need` (AllAccess satisfies anything).
inline bool hasRight(uint32_t granted, uint32_t need) {
    return (granted & R_AllAccess) || ((granted & need) == need);
}
std::string rightsToString(uint32_t rights);
uint32_t rightsFromStrings(const std::vector<std::string>& names); // parse config

enum class ConnectionMode : uint8_t {
    ViewOnly = 0,
    FullControl = 1,
    FileOnly = 2, // file management only; no screen stream
};

enum class AuthStatus : uint8_t {
    Ok            = 0,
    BadCredentials= 1,
    LockedOut     = 2,
    NotAuthorized = 3,
    ProtocolError = 4,
};

enum class FileOpStatus : uint8_t {
    Ok            = 0,
    Denied        = 1, // ACL / right missing
    NotFound      = 2,
    HashMismatch  = 3, // integrity check failed after transit
    IoError       = 4,
    TooLarge      = 5,
    BadPath       = 6, // traversal / outside sandbox
};

enum class PixelFormat : uint8_t { BGRA32 = 0 };

// ---------------------------------------------------------------------------
// One decoded frame off the transport.
struct Message {
    Op op;
    Bytes payload;
};

// ---------- typed messages (encode() => payload only, no frame header) ------
struct HelloMsg {
    uint16_t version = kProtocolVersion;
    std::string clientName;
    Bytes encode() const;
    static HelloMsg decode(const Bytes&);
};
struct ServerHelloMsg {
    uint16_t version = kProtocolVersion;
    std::string serverName;
    Bytes encode() const;
    static ServerHelloMsg decode(const Bytes&);
};
struct AuthRequestMsg {
    std::string username;
    std::string password; // cleared by caller ASAP after verify
    Bytes encode() const;
    static AuthRequestMsg decode(const Bytes&);
};
struct AuthResultMsg {
    AuthStatus status = AuthStatus::BadCredentials;
    uint32_t grantedRights = R_None;
    uint64_t sessionId = 0;
    Bytes encode() const;
    static AuthResultMsg decode(const Bytes&);
};
struct SessionStartMsg {
    ConnectionMode mode = ConnectionMode::ViewOnly;
    Bytes encode() const;
    static SessionStartMsg decode(const Bytes&);
};

struct FrameInfoMsg {
    uint32_t sequence = 0;
    uint16_t width = 0, height = 0;
    uint32_t stride = 0;
    PixelFormat format = PixelFormat::BGRA32;
    bool keyframe = false;
    Bytes encode() const;
    static FrameInfoMsg decode(const Bytes&);
};
struct FrameDataMsg {
    uint32_t sequence = 0;
    uint32_t offset = 0; // byte offset of this chunk within the frame buffer
    Bytes data;
    Bytes encode() const;
    static FrameDataMsg decode(const Bytes&);
};
// A single changed tile of a delta frame: `pixels` is w*4*h bytes, tightly
// packed, to be blitted into the client's persistent framebuffer at (x,y).
struct FrameRectMsg {
    uint32_t sequence = 0;
    uint16_t x = 0, y = 0, w = 0, h = 0;
    Bytes pixels;
    Bytes encode() const;
    static FrameRectMsg decode(const Bytes&);
};

// ---------- file-transfer transaction --------------------------------------
struct FileUploadReqMsg {
    std::string remotePath;
    uint64_t size = 0;
    Hash256 sha256{};
    Bytes encode() const;
    static FileUploadReqMsg decode(const Bytes&);
};
struct FileAcceptMsg {
    uint32_t transferId = 0;
    uint64_t size = 0;     // populated for downloads
    Hash256 sha256{};      // populated for downloads
    Bytes encode() const;
    static FileAcceptMsg decode(const Bytes&);
};
struct FileBlockMsg {
    uint32_t transferId = 0;
    uint32_t sequence = 0;
    Bytes data;
    Bytes encode() const;
    static FileBlockMsg decode(const Bytes&);
};
struct FileVerifyMsg {
    uint32_t transferId = 0;
    FileOpStatus status = FileOpStatus::Ok; // Ok or HashMismatch
    Bytes encode() const;
    static FileVerifyMsg decode(const Bytes&);
};
struct FileMoveMsg {
    std::string srcPath, dstPath;
    Bytes encode() const;
    static FileMoveMsg decode(const Bytes&);
};
struct FileDeleteMsg {
    std::string path;
    Bytes encode() const;
    static FileDeleteMsg decode(const Bytes&);
};
struct FileOpResultMsg {
    FileOpStatus status = FileOpStatus::Ok;
    std::string message;
    Bytes encode() const;
    static FileOpResultMsg decode(const Bytes&);
};
struct ErrorMsg {
    uint32_t code = 0;
    std::string message;
    Bytes encode() const;
    static ErrorMsg decode(const Bytes&);
};

} // namespace rp
