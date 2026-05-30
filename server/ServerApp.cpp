#include "server/ServerApp.h"

#include "common/Logger.h"
#include "common/Util.h"
#include "overlay/SessionOverlay.h"
#include "server/PrivilegeManager.h"
#include "video/ScreenCapture.h"
#include "video/VideoStreamer.h"

#include <windows.h>

#include <algorithm>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <map>
#include <optional>
#include <sstream>
#include <thread>

namespace fs = std::filesystem;

namespace rp {

namespace {

std::string trim(const std::string& s) {
    size_t a = s.find_first_not_of(" \t\r\n");
    if (a == std::string::npos) return "";
    size_t b = s.find_last_not_of(" \t\r\n");
    return s.substr(a, b - a + 1);
}

std::vector<std::string> splitAny(const std::string& s, const std::string& seps) {
    std::vector<std::string> out;
    std::string cur;
    for (char c : s) {
        if (seps.find(c) != std::string::npos) {
            if (!cur.empty()) { out.push_back(cur); cur.clear(); }
        } else {
            cur.push_back(c);
        }
    }
    if (!cur.empty()) out.push_back(cur);
    return out;
}

// Resolve `rel` under `root`, rejecting escapes (path traversal). Returns
// nullopt if the result would fall outside the sandbox root.
std::optional<fs::path> resolveInRoot(const fs::path& root, const std::string& rel) {
    std::error_code ec;
    fs::path canonRoot = fs::weakly_canonical(root, ec);
    if (ec) canonRoot = fs::absolute(root);
    fs::path candidate = fs::weakly_canonical(canonRoot / fs::path(rel), ec);
    if (ec) return std::nullopt;

    const auto r = canonRoot.native();
    const auto p = candidate.native();
    if (p.size() < r.size()) return std::nullopt;
    if (p.compare(0, r.size(), r) != 0) return std::nullopt;
    if (p.size() > r.size() && p[r.size()] != fs::path::preferred_separator) {
        return std::nullopt; // e.g. root="C:\share", candidate="C:\shareXYZ"
    }
    return candidate;
}

struct UploadState {
    fs::path finalPath;
    fs::path tempPath;
    std::ofstream out;
    uint64_t expected = 0;
    uint64_t received = 0;
    Hash256 declared{};
    Sha256 hasher;
};

void injectMouse(uint16_t x, uint16_t y, uint32_t action) {
    int sw = GetSystemMetrics(SM_CXSCREEN);
    int sh = GetSystemMetrics(SM_CYSCREEN);
    if (sw <= 1 || sh <= 1) return;
    INPUT in{};
    in.type = INPUT_MOUSE;
    in.mi.dx = static_cast<LONG>(MulDiv(x, 65535, sw - 1));
    in.mi.dy = static_cast<LONG>(MulDiv(y, 65535, sh - 1));
    in.mi.dwFlags = MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_MOVE;
    switch (action) {
        case 1: in.mi.dwFlags |= MOUSEEVENTF_LEFTDOWN; break;
        case 2: in.mi.dwFlags |= MOUSEEVENTF_LEFTUP; break;
        case 3: in.mi.dwFlags |= MOUSEEVENTF_RIGHTDOWN; break;
        case 4: in.mi.dwFlags |= MOUSEEVENTF_RIGHTUP; break;
        default: break;
    }
    SendInput(1, &in, sizeof(INPUT));
}

void injectKey(bool down, uint16_t vk) {
    INPUT in{};
    in.type = INPUT_KEYBOARD;
    in.ki.wVk = vk;
    in.ki.dwFlags = down ? 0 : KEYEVENTF_KEYUP;
    SendInput(1, &in, sizeof(INPUT));
}

} // namespace

// ---------------------------------------------------------------------------
ServerConfig ServerConfig::parse(const std::string& text) {
    ServerConfig c;
    std::map<std::string, UserRecord> users;

    std::istringstream in(text);
    std::string line;
    while (std::getline(in, line)) {
        line = trim(line);
        if (line.empty() || line[0] == '#' || line[0] == ';') continue;
        auto eq = line.find('=');
        if (eq == std::string::npos) continue;
        std::string key = trim(line.substr(0, eq));
        std::string val = trim(line.substr(eq + 1));

        if (key == "port") c.port = static_cast<uint16_t>(std::atoi(val.c_str()));
        else if (key == "bind") c.bindAddr = val;
        else if (key == "monitor") c.monitor = static_cast<uint32_t>(std::atoi(val.c_str()));
        else if (key == "allow_subnets") c.allowSubnets = val;
        else if (key == "tls_cert") c.tlsCert = val;
        else if (key == "tls_key") c.tlsKey = val;
        else if (key == "client_ca") c.clientCa = val;
        else if (key == "audit_csv") c.auditCsv = val;
        else if (key == "file_root") c.fileRoot = val;
        else if (key == "max_sessions") c.maxSessions = static_cast<uint32_t>(std::atoi(val.c_str()));
        else if (key.rfind("user.", 0) == 0) {
            // user.<name>.<field>
            std::string rest = key.substr(5);
            auto dot = rest.rfind('.');
            if (dot == std::string::npos) continue;
            std::string name = rest.substr(0, dot);
            std::string field = rest.substr(dot + 1);
            users[name].username = name;
            if (field == "hash") users[name].argon2Hash = val;
            else if (field == "rights") users[name].rights = rightsFromStrings(splitAny(val, "|,"));
        }
    }
    for (auto& kv : users) c.users.push_back(kv.second);
    return c;
}

// ---------------------------------------------------------------------------
ServerApp::ServerApp(ServerConfig cfg) : cfg_(std::move(cfg)) {}

int ServerApp::run() {
    ensureWinsock();

    // Least privilege: warn loudly if the steady-state server is elevated.
    if (PrivilegeManager::isElevated()) {
        RP_LOG_WARN("server is running ELEVATED; for least privilege run it as a "
                    "standard user and let it escalate per-task via UAC.");
    }

    try {
        tls_ = TlsContext::makeServer({cfg_.tlsCert, cfg_.tlsKey, cfg_.clientCa});
    } catch (const std::exception& e) {
        RP_LOG_ERROR(std::string("TLS init failed: ") + e.what());
        return 2;
    }

    SubnetFilter filter;
    size_t n = filter.addList(cfg_.allowSubnets);
    if (n == 0) {
        RP_LOG_ERROR("no valid allow_subnets configured - refusing to start "
                     "(fail closed). Set e.g. allow_subnets=192.168.1.0/24");
        return 3;
    }

    sec_ = std::make_shared<SecurityManager>(tls_, std::move(filter));

    // Self-defined local users only: each needs an Argon2id hash in the config.
    for (auto& u : cfg_.users) {
        if (u.argon2Hash.empty()) {
            RP_LOG_WARN("user '" + u.username + "' has no password hash - skipping");
            continue;
        }
        sec_->addUser(u);
    }
    if (sec_->userCount() == 0) {
        RP_LOG_ERROR("no users configured - refusing to start");
        return 4;
    }

    try {
        audit_ = std::make_unique<AuditLogger>(cfg_.auditCsv);
    } catch (const std::exception& e) {
        RP_LOG_ERROR(std::string("audit log init failed: ") + e.what());
        return 5;
    }

    std::error_code ec;
    fs::create_directories(cfg_.fileRoot, ec);

    if (!listener_.listen(cfg_.bindAddr, cfg_.port)) {
        RP_LOG_ERROR("cannot listen on " + cfg_.bindAddr + ":" + std::to_string(cfg_.port));
        return 6;
    }
    RP_LOG_INFO("radminpro server listening on " + cfg_.bindAddr + ":" +
                std::to_string(cfg_.port) + " | users=" + std::to_string(sec_->userCount()) +
                " | allow-list=" + std::to_string(n) + " range(s)");

    while (running_.load()) {
        PeerInfo peer;
        socket_t fd = listener_.accept(peer);
        if (fd == kInvalidSocket) {
            if (!running_.load()) break; // clean stop() via close()
            RP_LOG_WARN("accept() failed");
            continue;
        }

        // Anti-tampering gate: reject foreign subnets BEFORE the TLS stack.
        if (!sec_->isPeerAllowed(peer.ip)) {
            audit_->connection(peer.toString(), false, "outside allow-list");
            RP_LOG_WARN("rejected connection from " + peer.toString() + " (not in allow-list)");
            closeSocket(fd);
            continue;
        }
        // Concurrent-session cap (cheap DoS protection). accept() is the only
        // incrementer; each session decrements via an RAII guard on exit.
        if (activeSessions_.fetch_add(1) >= cfg_.maxSessions) {
            activeSessions_.fetch_sub(1);
            audit_->connection(peer.toString(), false, "session cap reached");
            RP_LOG_WARN("rejecting " + peer.toString() + ": max sessions reached");
            closeSocket(fd);
            continue;
        }
        audit_->connection(peer.toString(), true, "");

        auto transport = SocketTransport::wrap(fd, *tls_, peer);
        if (!transport) {
            activeSessions_.fetch_sub(1);
            RP_LOG_ERROR("failed to wrap socket for " + peer.toString());
            continue;
        }
        std::thread(&ServerApp::session, this, std::move(transport), peer).detach();
    }

    listener_.close();
    return 0;
}

void ServerApp::stop() {
    running_.store(false);
    listener_.close(); // breaks the blocked accept() in run()
}

std::string ServerApp::serialize(const ServerConfig& cfg) {
    std::ostringstream o;
    o << "bind=" << cfg.bindAddr << "\n";
    o << "port=" << cfg.port << "\n";
    o << "monitor=" << cfg.monitor << "\n";
    o << "allow_subnets=" << cfg.allowSubnets << "\n";
    o << "tls_cert=" << cfg.tlsCert << "\n";
    o << "tls_key=" << cfg.tlsKey << "\n";
    if (!cfg.clientCa.empty()) o << "client_ca=" << cfg.clientCa << "\n";
    o << "audit_csv=" << cfg.auditCsv << "\n";
    o << "file_root=" << cfg.fileRoot << "\n";
    o << "max_sessions=" << cfg.maxSessions << "\n";
    for (const auto& u : cfg.users) {
        if (u.username.empty() || u.argon2Hash.empty()) continue;
        o << "user." << u.username << ".hash=" << u.argon2Hash << "\n";
        o << "user." << u.username << ".rights=" << rightsToString(u.rights) << "\n";
    }
    return o.str();
}

// ---------------------------------------------------------------------------
void ServerApp::session(std::unique_ptr<SocketTransport> tp, PeerInfo peer) {
    SocketTransport& t = *tp;
    const std::string peerStr = peer.toString();

    // Release the concurrent-session slot however we exit (incl. early returns).
    struct SessionGuard {
        std::atomic<uint32_t>& c;
        ~SessionGuard() { c.fetch_sub(1); }
    } sessionGuard{activeSessions_};

    // Bound the handshake/auth phase: a client that connects but never completes
    // the TLS+auth exchange cannot pin this thread indefinitely.
    t.setRecvTimeoutMs(15000);

    if (!t.handshake()) {
        audit_->auth("-", peerStr, false, "tls_handshake_failed");
        return;
    }

    Message m;
    // --- Hello / ServerHello ---
    if (!t.readMessage(m) || m.op != Op::Hello) return;
    if (HelloMsg::decode(m.payload).version != kProtocolVersion) {
        t.writeMessage(Op::Error, ErrorMsg{1, "protocol version mismatch"}.encode());
        return;
    }
    {
        ServerHelloMsg sh;
        sh.serverName = "radminpro";
        t.writeMessage(Op::ServerHello, sh.encode());
    }

    // --- Authentication ---
    if (!t.readMessage(m) || m.op != Op::AuthRequest) return;
    AuthRequestMsg areq = AuthRequestMsg::decode(m.payload);
    const std::string user = areq.username;
    AuthOutcome ao = sec_->authenticate(areq.username, std::move(areq.password), peer.ip);
    secureZero(areq.password);

    AuthResultMsg ares;
    ares.status = ao.status;
    ares.grantedRights = ao.rights;
    if (ao.status == AuthStatus::Ok) {
        Bytes r = randomBytes(8);
        ByteReader br(r);
        ares.sessionId = br.u64();
    }
    t.writeMessage(Op::AuthResult, ares.encode());

    audit_->auth(user, peerStr, ao.status == AuthStatus::Ok,
                 ao.status == AuthStatus::Ok ? rightsToString(ao.rights)
                                             : "status=" + std::to_string((int)ao.status));
    if (ao.status != AuthStatus::Ok) {
        RP_LOG_WARN("auth failed for '" + user + "' from " + peerStr);
        return;
    }
    const uint32_t rights = ao.rights;

    // --- Session mode ---
    if (!t.readMessage(m) || m.op != Op::SessionStart) return;
    const ConnectionMode mode = SessionStartMsg::decode(m.payload).mode;
    const bool hasControl = hasRight(rights, R_RemoteScreenControl);
    const bool hasViewRight = hasControl || hasRight(rights, R_RemoteScreenView);

    bool authorized = false;
    std::string modeStr;
    switch (mode) {
        case ConnectionMode::FullControl: authorized = hasControl; modeStr = "Full Control"; break;
        case ConnectionMode::ViewOnly:    authorized = hasViewRight; modeStr = "View Only"; break;
        case ConnectionMode::FileOnly:    authorized = hasRight(rights, R_FileTransfer);
                                          modeStr = "File Transfer"; break;
    }
    if (!authorized) {
        t.writeMessage(Op::Error, ErrorMsg{2, "not authorized for requested mode"}.encode());
        audit_->fileOp(AuditAction::PermissionDenied, user, peerStr, "",
                       "DENIED", "session mode=" + modeStr);
        return;
    }

    const bool canControl = (mode == ConnectionMode::FullControl) && hasControl;
    const bool canView = (mode != ConnectionMode::FileOnly) && hasViewRight;

    // Authenticated session established: drop the handshake recv timeout. The
    // event loop below paces itself with select() (readMessageTimed), so the
    // socket should block normally between events / during file transfers.
    t.setRecvTimeoutMs(0);

    // --- Mandatory on-screen indicator (anti-covert-spying) ---
    SessionOverlay overlay;
    overlay.show("Remote session active  -  " + user + "  from  " + peer.ip + "   (" + modeStr + ")");
    audit_->session(user, peerStr, true, "mode=" + modeStr);
    RP_LOG_INFO("session start: " + user + "@" + peerStr + " (" + modeStr + ")");

    // --- Video ---
    ScreenCapture capture;
    bool captureOk = capture.initialize(cfg_.monitor);
    if (!captureOk) RP_LOG_WARN("screen capture unavailable; continuing without video");
    VideoStreamer streamer(capture,
                           [&t](Op op, const Bytes& p) { return t.writeMessage(op, p); });

    // --- File-transfer transaction state ---
    std::map<uint32_t, std::unique_ptr<UploadState>> uploads;
    uint32_t nextTransferId = 1;
    const fs::path root = cfg_.fileRoot;

    auto sendOpResult = [&](FileOpStatus st, const std::string& msg) {
        t.writeMessage(Op::FileOpResult, FileOpResultMsg{st, msg}.encode());
    };

    auto handle = [&](const Message& in) -> bool {
        switch (in.op) {
            case Op::Bye:
                return false;

            case Op::InputMouse: {
                if (!canControl) break; // silently ignore in view-only
                ByteReader r(in.payload);
                uint16_t x = r.u16(), y = r.u16();
                uint32_t action = r.u32();
                injectMouse(x, y, action);
                break;
            }
            case Op::InputKey: {
                if (!canControl) break;
                ByteReader r(in.payload);
                uint8_t down = r.u8();
                uint16_t vk = r.u16();
                injectKey(down != 0, vk);
                break;
            }

            case Op::FileUploadReq: {
                if (!hasRight(rights, R_FileTransfer)) {
                    audit_->fileOp(AuditAction::PermissionDenied, user, peerStr, "",
                                   "DENIED", "upload");
                    sendOpResult(FileOpStatus::Denied, "file transfer not permitted");
                    break;
                }
                FileUploadReqMsg req = FileUploadReqMsg::decode(in.payload);
                auto dest = resolveInRoot(root, req.remotePath);
                if (!dest) {
                    audit_->fileOp(AuditAction::FileUpload, user, peerStr, req.remotePath,
                                   "DENIED", "path outside sandbox");
                    sendOpResult(FileOpStatus::BadPath, "path rejected");
                    break;
                }
                auto st = std::make_unique<UploadState>();
                st->finalPath = *dest;
                st->tempPath = dest->string() + ".part";
                st->expected = req.size;
                st->declared = req.sha256;
                std::error_code ec;
                fs::create_directories(dest->parent_path(), ec);
                st->out.open(st->tempPath, std::ios::binary | std::ios::trunc);
                if (!st->out.is_open()) {
                    sendOpResult(FileOpStatus::IoError, "cannot create file");
                    break;
                }
                uint32_t id = nextTransferId++;
                FileAcceptMsg acc;
                acc.transferId = id;
                uploads[id] = std::move(st);
                t.writeMessage(Op::FileAccept, acc.encode());
                break;
            }
            case Op::FileBlock: {
                FileBlockMsg blk = FileBlockMsg::decode(in.payload);
                auto it = uploads.find(blk.transferId);
                if (it == uploads.end()) break;
                auto& st = *it->second;
                st.out.write(reinterpret_cast<const char*>(blk.data.data()),
                             static_cast<std::streamsize>(blk.data.size()));
                st.hasher.update(blk.data.data(), blk.data.size());
                st.received += blk.data.size();
                break;
            }
            case Op::FileComplete: {
                ByteReader r(in.payload);
                uint32_t id = r.u32();
                auto it = uploads.find(id);
                if (it == uploads.end()) break;
                auto& st = *it->second;
                st.out.close();

                // Integrity: recompute hash and compare to the client's claim.
                Hash256 actual = st.hasher.finish();
                const bool sizeOk = (st.received == st.expected);
                const bool hashOk = (actual == st.declared);
                std::error_code ec;
                if (sizeOk && hashOk) {
                    fs::rename(st.tempPath, st.finalPath, ec);
                    if (ec) {
                        fs::remove(st.tempPath, ec);
                        t.writeMessage(Op::FileVerify,
                                       FileVerifyMsg{id, FileOpStatus::IoError}.encode());
                        audit_->fileOp(AuditAction::FileUpload, user, peerStr,
                                       st.finalPath.string(), "IO_ERROR", "rename failed");
                    } else {
                        t.writeMessage(Op::FileVerify,
                                       FileVerifyMsg{id, FileOpStatus::Ok}.encode());
                        audit_->fileOp(AuditAction::FileUpload, user, peerStr,
                                       st.finalPath.string(), "OK",
                                       "sha256=" + toHex(actual));
                    }
                } else {
                    fs::remove(st.tempPath, ec);
                    t.writeMessage(Op::FileVerify,
                                   FileVerifyMsg{id, FileOpStatus::HashMismatch}.encode());
                    audit_->fileOp(AuditAction::IntegrityFail, user, peerStr,
                                   st.finalPath.string(), "MISMATCH",
                                   sizeOk ? "hash differs" : "size differs");
                }
                uploads.erase(it);
                break;
            }

            case Op::FileDelete: {
                if (!hasRight(rights, R_FileTransfer)) {
                    audit_->fileOp(AuditAction::PermissionDenied, user, peerStr, "",
                                   "DENIED", "delete");
                    sendOpResult(FileOpStatus::Denied, "not permitted");
                    break;
                }
                FileDeleteMsg del = FileDeleteMsg::decode(in.payload);
                auto target = resolveInRoot(root, del.path);
                if (!target) {
                    audit_->fileOp(AuditAction::FileDelete, user, peerStr, del.path,
                                   "DENIED", "path outside sandbox");
                    sendOpResult(FileOpStatus::BadPath, "path rejected");
                    break;
                }
                std::error_code ec;
                bool ok = fs::remove(*target, ec);
                audit_->fileOp(AuditAction::FileDelete, user, peerStr, target->string(),
                               ok ? "OK" : "FAIL", ec.message());
                sendOpResult(ok ? FileOpStatus::Ok : FileOpStatus::NotFound, ec.message());
                break;
            }
            case Op::FileMove: {
                if (!hasRight(rights, R_FileTransfer)) {
                    audit_->fileOp(AuditAction::PermissionDenied, user, peerStr, "",
                                   "DENIED", "move");
                    sendOpResult(FileOpStatus::Denied, "not permitted");
                    break;
                }
                FileMoveMsg mv = FileMoveMsg::decode(in.payload);
                auto src = resolveInRoot(root, mv.srcPath);
                auto dst = resolveInRoot(root, mv.dstPath);
                if (!src || !dst) {
                    audit_->fileOp(AuditAction::FileMove, user, peerStr,
                                   mv.srcPath + " -> " + mv.dstPath, "DENIED",
                                   "path outside sandbox");
                    sendOpResult(FileOpStatus::BadPath, "path rejected");
                    break;
                }
                std::error_code ec;
                fs::rename(*src, *dst, ec);
                audit_->fileOp(AuditAction::FileMove, user, peerStr,
                               src->string() + " -> " + dst->string(),
                               ec ? "FAIL" : "OK", ec.message());
                sendOpResult(ec ? FileOpStatus::IoError : FileOpStatus::Ok, ec.message());
                break;
            }

            case Op::FileDownloadReq: {
                if (!hasRight(rights, R_FileTransfer)) {
                    audit_->fileOp(AuditAction::PermissionDenied, user, peerStr, "",
                                   "DENIED", "download");
                    sendOpResult(FileOpStatus::Denied, "not permitted");
                    break;
                }
                ByteReader r(in.payload);
                std::string relPath = r.str();
                auto src = resolveInRoot(root, relPath);
                if (!src) {
                    audit_->fileOp(AuditAction::FileDownload, user, peerStr, relPath,
                                   "DENIED", "path outside sandbox");
                    sendOpResult(FileOpStatus::BadPath, "path rejected");
                    break;
                }
                std::ifstream f(*src, std::ios::binary);
                if (!f) {
                    sendOpResult(FileOpStatus::NotFound, "no such file");
                    break;
                }
                Bytes data((std::istreambuf_iterator<char>(f)),
                           std::istreambuf_iterator<char>());
                Hash256 h = sha256(data);
                uint32_t id = nextTransferId++;
                FileAcceptMsg acc;
                acc.transferId = id;
                acc.size = data.size();
                acc.sha256 = h;
                t.writeMessage(Op::FileAccept, acc.encode());
                for (size_t off = 0; off < data.size(); off += kFileBlockSize) {
                    size_t n = std::min<size_t>(kFileBlockSize, data.size() - off);
                    FileBlockMsg blk;
                    blk.transferId = id;
                    blk.sequence = static_cast<uint32_t>(off / kFileBlockSize);
                    blk.data.assign(data.begin() + off, data.begin() + off + n);
                    if (!t.writeMessage(Op::FileBlock, blk.encode())) break;
                }
                Bytes endp;
                putU32(endp, id);
                t.writeMessage(Op::FileComplete, endp);
                audit_->fileOp(AuditAction::FileDownload, user, peerStr, src->string(),
                               "OK", "sha256=" + toHex(h));
                break;
            }
            case Op::FileVerify: {
                // Client's post-download integrity receipt.
                FileVerifyMsg v = FileVerifyMsg::decode(in.payload);
                if (v.status != FileOpStatus::Ok) {
                    audit_->fileOp(AuditAction::IntegrityFail, user, peerStr, "",
                                   "MISMATCH", "client reported download hash mismatch");
                }
                break;
            }

            default:
                break;
        }
        return true;
    };

    // --- Single-threaded session event loop ---
    // One thread services both directions, so a single SSL object is never used
    // concurrently. readMessageTimed(5ms) yields quickly so video keeps flowing.
    while (running_.load()) {
        Message in;
        auto rr = t.readMessageTimed(in, 5);
        if (rr == SocketTransport::ReadResult::Closed) break;
        if (rr == SocketTransport::ReadResult::Ok && !handle(in)) break;

        if (canView && captureOk) {
            VideoStreamer::Step step = streamer.streamOnce(0);
            if (step == VideoStreamer::Step::Lost) {
                captureOk = capture.initialize(cfg_.monitor);
            } else if (step == VideoStreamer::Step::Error) {
                break;
            }
        }
    }

    // Discard any in-flight upload temp files that never completed.
    for (auto& kv : uploads) {
        if (kv.second) {
            kv.second->out.close();
            std::error_code ec;
            fs::remove(kv.second->tempPath, ec);
        }
    }

    audit_->session(user, peerStr, false, "");
    overlay.hide();
    RP_LOG_INFO("session end: " + user + "@" + peerStr);
}

} // namespace rp
