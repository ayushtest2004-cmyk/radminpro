#include "common/Protocol.h"

#include <algorithm>

namespace rp {

const char* opName(Op op) {
    switch (op) {
        case Op::Hello: return "Hello";
        case Op::ServerHello: return "ServerHello";
        case Op::AuthRequest: return "AuthRequest";
        case Op::AuthResult: return "AuthResult";
        case Op::SessionStart: return "SessionStart";
        case Op::FrameInfo: return "FrameInfo";
        case Op::FrameData: return "FrameData";
        case Op::FrameEnd: return "FrameEnd";
        case Op::FrameRect: return "FrameRect";
        case Op::InputMouse: return "InputMouse";
        case Op::InputKey: return "InputKey";
        case Op::FileUploadReq: return "FileUploadReq";
        case Op::FileDownloadReq: return "FileDownloadReq";
        case Op::FileAccept: return "FileAccept";
        case Op::FileReject: return "FileReject";
        case Op::FileBlock: return "FileBlock";
        case Op::FileComplete: return "FileComplete";
        case Op::FileVerify: return "FileVerify";
        case Op::FileMove: return "FileMove";
        case Op::FileDelete: return "FileDelete";
        case Op::FileOpResult: return "FileOpResult";
        case Op::Error: return "Error";
        case Op::Ping: return "Ping";
        case Op::Bye: return "Bye";
    }
    return "Unknown";
}

namespace {
struct RightDef { uint32_t bit; const char* name; };
const RightDef kRights[] = {
    {R_AllAccess, "AllAccess"},
    {R_RemoteScreenView, "RemoteScreenView"},
    {R_RemoteScreenControl, "RemoteScreenControl"},
    {R_FileTransfer, "FileTransfer"},
    {R_Chat, "Chat"},
    {R_SendMessage, "SendMessage"},
    {R_Shutdown, "Shutdown"},
    {R_Redirect, "Redirect"},
    {R_Telnet, "Telnet"},
    {R_VoiceChat, "VoiceChat"},
};
} // namespace

std::string rightsToString(uint32_t rights) {
    if (rights == R_None) return "None";
    std::string s;
    for (const auto& r : kRights) {
        if (rights & r.bit) {
            if (!s.empty()) s += "|";
            s += r.name;
        }
    }
    return s.empty() ? "None" : s;
}

uint32_t rightsFromStrings(const std::vector<std::string>& names) {
    uint32_t out = R_None;
    for (const auto& n : names) {
        for (const auto& r : kRights) {
            if (n == r.name) { out |= r.bit; break; }
        }
    }
    return out;
}

// --- helpers for the fixed-size hash field ---------------------------------
static void putHash(Bytes& out, const Hash256& h) { putBytes(out, h.data(), h.size()); }
static Hash256 getHash(ByteReader& r) {
    Bytes b = r.bytes(32);
    Hash256 h{};
    std::copy(b.begin(), b.end(), h.begin());
    return h;
}

// --- Hello ------------------------------------------------------------------
Bytes HelloMsg::encode() const {
    Bytes b;
    putU16(b, version);
    putString(b, clientName);
    return b;
}
HelloMsg HelloMsg::decode(const Bytes& p) {
    ByteReader r(p);
    HelloMsg m;
    m.version = r.u16();
    m.clientName = r.str();
    return m;
}

Bytes ServerHelloMsg::encode() const {
    Bytes b;
    putU16(b, version);
    putString(b, serverName);
    return b;
}
ServerHelloMsg ServerHelloMsg::decode(const Bytes& p) {
    ByteReader r(p);
    ServerHelloMsg m;
    m.version = r.u16();
    m.serverName = r.str();
    return m;
}

// --- Auth -------------------------------------------------------------------
Bytes AuthRequestMsg::encode() const {
    Bytes b;
    putString(b, username);
    putString(b, password);
    return b;
}
AuthRequestMsg AuthRequestMsg::decode(const Bytes& p) {
    ByteReader r(p);
    AuthRequestMsg m;
    m.username = r.str();
    m.password = r.str();
    return m;
}

Bytes AuthResultMsg::encode() const {
    Bytes b;
    putU8(b, static_cast<uint8_t>(status));
    putU32(b, grantedRights);
    putU64(b, sessionId);
    return b;
}
AuthResultMsg AuthResultMsg::decode(const Bytes& p) {
    ByteReader r(p);
    AuthResultMsg m;
    m.status = static_cast<AuthStatus>(r.u8());
    m.grantedRights = r.u32();
    m.sessionId = r.u64();
    return m;
}

Bytes SessionStartMsg::encode() const {
    Bytes b;
    putU8(b, static_cast<uint8_t>(mode));
    return b;
}
SessionStartMsg SessionStartMsg::decode(const Bytes& p) {
    ByteReader r(p);
    SessionStartMsg m;
    m.mode = static_cast<ConnectionMode>(r.u8());
    return m;
}

// --- Frames -----------------------------------------------------------------
Bytes FrameInfoMsg::encode() const {
    Bytes b;
    putU32(b, sequence);
    putU16(b, width);
    putU16(b, height);
    putU32(b, stride);
    putU8(b, static_cast<uint8_t>(format));
    putU8(b, keyframe ? 1 : 0);
    return b;
}
FrameInfoMsg FrameInfoMsg::decode(const Bytes& p) {
    ByteReader r(p);
    FrameInfoMsg m;
    m.sequence = r.u32();
    m.width = r.u16();
    m.height = r.u16();
    m.stride = r.u32();
    m.format = static_cast<PixelFormat>(r.u8());
    m.keyframe = r.u8() != 0;
    return m;
}

Bytes FrameDataMsg::encode() const {
    Bytes b;
    putU32(b, sequence);
    putU32(b, offset);
    putBlob(b, data.data(), data.size());
    return b;
}
FrameDataMsg FrameDataMsg::decode(const Bytes& p) {
    ByteReader r(p);
    FrameDataMsg m;
    m.sequence = r.u32();
    m.offset = r.u32();
    m.data = r.blob();
    return m;
}

Bytes FrameRectMsg::encode() const {
    Bytes b;
    putU32(b, sequence);
    putU16(b, x);
    putU16(b, y);
    putU16(b, w);
    putU16(b, h);
    putBlob(b, pixels.data(), pixels.size());
    return b;
}
FrameRectMsg FrameRectMsg::decode(const Bytes& p) {
    ByteReader r(p);
    FrameRectMsg m;
    m.sequence = r.u32();
    m.x = r.u16();
    m.y = r.u16();
    m.w = r.u16();
    m.h = r.u16();
    m.pixels = r.blob();
    return m;
}

// --- File transfer ----------------------------------------------------------
Bytes FileUploadReqMsg::encode() const {
    Bytes b;
    putString(b, remotePath);
    putU64(b, size);
    putHash(b, sha256);
    return b;
}
FileUploadReqMsg FileUploadReqMsg::decode(const Bytes& p) {
    ByteReader r(p);
    FileUploadReqMsg m;
    m.remotePath = r.str();
    m.size = r.u64();
    m.sha256 = getHash(r);
    return m;
}

Bytes FileAcceptMsg::encode() const {
    Bytes b;
    putU32(b, transferId);
    putU64(b, size);
    putHash(b, sha256);
    return b;
}
FileAcceptMsg FileAcceptMsg::decode(const Bytes& p) {
    ByteReader r(p);
    FileAcceptMsg m;
    m.transferId = r.u32();
    m.size = r.u64();
    m.sha256 = getHash(r);
    return m;
}

Bytes FileBlockMsg::encode() const {
    Bytes b;
    putU32(b, transferId);
    putU32(b, sequence);
    putBlob(b, data.data(), data.size());
    return b;
}
FileBlockMsg FileBlockMsg::decode(const Bytes& p) {
    ByteReader r(p);
    FileBlockMsg m;
    m.transferId = r.u32();
    m.sequence = r.u32();
    m.data = r.blob();
    return m;
}

Bytes FileVerifyMsg::encode() const {
    Bytes b;
    putU32(b, transferId);
    putU8(b, static_cast<uint8_t>(status));
    return b;
}
FileVerifyMsg FileVerifyMsg::decode(const Bytes& p) {
    ByteReader r(p);
    FileVerifyMsg m;
    m.transferId = r.u32();
    m.status = static_cast<FileOpStatus>(r.u8());
    return m;
}

Bytes FileMoveMsg::encode() const {
    Bytes b;
    putString(b, srcPath);
    putString(b, dstPath);
    return b;
}
FileMoveMsg FileMoveMsg::decode(const Bytes& p) {
    ByteReader r(p);
    FileMoveMsg m;
    m.srcPath = r.str();
    m.dstPath = r.str();
    return m;
}

Bytes FileDeleteMsg::encode() const {
    Bytes b;
    putString(b, path);
    return b;
}
FileDeleteMsg FileDeleteMsg::decode(const Bytes& p) {
    ByteReader r(p);
    FileDeleteMsg m;
    m.path = r.str();
    return m;
}

Bytes FileOpResultMsg::encode() const {
    Bytes b;
    putU8(b, static_cast<uint8_t>(status));
    putString(b, message);
    return b;
}
FileOpResultMsg FileOpResultMsg::decode(const Bytes& p) {
    ByteReader r(p);
    FileOpResultMsg m;
    m.status = static_cast<FileOpStatus>(r.u8());
    m.message = r.str();
    return m;
}

Bytes ErrorMsg::encode() const {
    Bytes b;
    putU32(b, code);
    putString(b, message);
    return b;
}
ErrorMsg ErrorMsg::decode(const Bytes& p) {
    ByteReader r(p);
    ErrorMsg m;
    m.code = r.u32();
    m.message = r.str();
    return m;
}

} // namespace rp
