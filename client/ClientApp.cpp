#include "client/ClientApp.h"

#include "common/Logger.h"
#include "common/Util.h"

#include <windows.h>
#include <windowsx.h>

#include <algorithm>
#include <atomic>
#include <cstring>
#include <fstream>
#include <iterator>
#include <mutex>
#include <thread>
#include <vector>

namespace rp {

ClientApp::ClientApp(ClientConfig cfg) : cfg_(std::move(cfg)) {}

bool ClientApp::connectAndAuth() {
    ensureWinsock();

    TlsContext::ClientConfig cc;
    cc.caPath = cfg_.caPath;
    cc.pinnedSha256Hex = cfg_.pinSha256Hex;
    cc.requireVerification = true; // secure by default
    try {
        tls_ = TlsContext::makeClient(cc);
    } catch (const std::exception& e) {
        RP_LOG_ERROR(std::string("TLS client init failed: ") + e.what() +
                     " (provide --pin <sha256> or --ca <file>)");
        return false;
    }

    socket_t fd = tcpConnect(cfg_.host, cfg_.port);
    if (fd == kInvalidSocket) {
        RP_LOG_ERROR("connect to " + cfg_.host + ":" + std::to_string(cfg_.port) + " failed");
        return false;
    }
    t_ = SocketTransport::wrap(fd, *tls_, PeerInfo{cfg_.host, cfg_.port});
    if (!t_ || !t_->handshake()) {
        RP_LOG_ERROR("TLS handshake failed (certificate pin mismatch?)");
        return false;
    }

    HelloMsg hello;
    hello.clientName = "radminpro-client";
    t_->writeMessage(Op::Hello, hello.encode());

    Message m;
    if (!t_->readMessage(m) || m.op != Op::ServerHello) {
        RP_LOG_ERROR("server did not greet (op mismatch)");
        return false;
    }

    AuthRequestMsg areq;
    areq.username = cfg_.username;
    areq.password = cfg_.password;
    t_->writeMessage(Op::AuthRequest, areq.encode());
    secureZero(areq.password);
    secureZero(cfg_.password);

    if (!t_->readMessage(m) || m.op != Op::AuthResult) {
        if (m.op == Op::Error) RP_LOG_ERROR("server error: " + ErrorMsg::decode(m.payload).message);
        return false;
    }
    AuthResultMsg ares = AuthResultMsg::decode(m.payload);
    if (ares.status != AuthStatus::Ok) {
        RP_LOG_ERROR("authentication failed (status=" +
                     std::to_string(static_cast<int>(ares.status)) + ")");
        return false;
    }
    rights_ = ares.grantedRights;
    RP_LOG_INFO("authenticated; granted rights: " + rightsToString(rights_));

    SessionStartMsg ss;
    ss.mode = cfg_.mode;
    t_->writeMessage(Op::SessionStart, ss.encode());

    // The server replies with Error only if the mode is not authorized.
    // (For accepted sessions it begins streaming / awaits file ops.)
    return true;
}

// ---------------------------------------------------------------------------
// File-transfer transactions
// ---------------------------------------------------------------------------
bool ClientApp::uploadFile(const std::string& localPath, const std::string& remotePath) {
    std::ifstream f(localPath, std::ios::binary);
    if (!f) {
        RP_LOG_ERROR("cannot open local file: " + localPath);
        return false;
    }
    Bytes data((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());

    FileUploadReqMsg req;
    req.remotePath = remotePath;
    req.size = data.size();
    req.sha256 = sha256(data);
    t_->writeMessage(Op::FileUploadReq, req.encode());

    Message m;
    if (!t_->readMessage(m)) return false;
    if (m.op == Op::FileOpResult) {
        RP_LOG_ERROR("upload rejected: " + FileOpResultMsg::decode(m.payload).message);
        return false;
    }
    if (m.op != Op::FileAccept) return false;
    uint32_t id = FileAcceptMsg::decode(m.payload).transferId;

    for (size_t off = 0; off < data.size(); off += kFileBlockSize) {
        size_t n = std::min<size_t>(kFileBlockSize, data.size() - off);
        FileBlockMsg blk;
        blk.transferId = id;
        blk.sequence = static_cast<uint32_t>(off / kFileBlockSize);
        blk.data.assign(data.begin() + off, data.begin() + off + n);
        if (!t_->writeMessage(Op::FileBlock, blk.encode())) return false;
    }
    Bytes endp;
    putU32(endp, id);
    t_->writeMessage(Op::FileComplete, endp);

    if (!t_->readMessage(m) || m.op != Op::FileVerify) return false;
    FileVerifyMsg v = FileVerifyMsg::decode(m.payload);
    bool ok = (v.status == FileOpStatus::Ok);
    RP_LOG_INFO(ok ? "upload verified OK (server hash matched)"
                   : "upload FAILED integrity check on server");
    return ok;
}

bool ClientApp::downloadFile(const std::string& remotePath, const std::string& localPath) {
    Bytes p;
    putString(p, remotePath);
    t_->writeMessage(Op::FileDownloadReq, p);

    Message m;
    if (!t_->readMessage(m)) return false;
    if (m.op == Op::FileOpResult) {
        RP_LOG_ERROR("download rejected: " + FileOpResultMsg::decode(m.payload).message);
        return false;
    }
    if (m.op != Op::FileAccept) return false;
    FileAcceptMsg acc = FileAcceptMsg::decode(m.payload);

    std::ofstream out(localPath, std::ios::binary | std::ios::trunc);
    if (!out) {
        RP_LOG_ERROR("cannot create local file: " + localPath);
        return false;
    }
    Sha256 hasher;
    uint64_t got = 0;
    for (;;) {
        if (!t_->readMessage(m)) return false;
        if (m.op == Op::FileBlock) {
            FileBlockMsg b = FileBlockMsg::decode(m.payload);
            if (b.transferId != acc.transferId) continue;
            out.write(reinterpret_cast<const char*>(b.data.data()),
                      static_cast<std::streamsize>(b.data.size()));
            hasher.update(b.data.data(), b.data.size());
            got += b.data.size();
        } else if (m.op == Op::FileComplete) {
            break;
        } else if (m.op == Op::Error) {
            return false;
        }
    }
    out.close();

    Hash256 actual = hasher.finish();
    bool ok = (got == acc.size) && (actual == acc.sha256);
    // Send integrity receipt so the server can audit the download.
    t_->writeMessage(Op::FileVerify,
                     FileVerifyMsg{acc.transferId,
                                   ok ? FileOpStatus::Ok : FileOpStatus::HashMismatch}
                         .encode());
    RP_LOG_INFO(ok ? "download verified OK (hash matched)"
                   : "download FAILED integrity check");
    return ok;
}

bool ClientApp::deleteRemote(const std::string& remotePath) {
    FileDeleteMsg d;
    d.path = remotePath;
    t_->writeMessage(Op::FileDelete, d.encode());
    Message m;
    if (!t_->readMessage(m) || m.op != Op::FileOpResult) return false;
    FileOpResultMsg r = FileOpResultMsg::decode(m.payload);
    bool ok = (r.status == FileOpStatus::Ok);
    RP_LOG_INFO("delete '" + remotePath + "': " + (ok ? "OK" : ("FAILED " + r.message)));
    return ok;
}

bool ClientApp::moveRemote(const std::string& src, const std::string& dst) {
    FileMoveMsg mv;
    mv.srcPath = src;
    mv.dstPath = dst;
    t_->writeMessage(Op::FileMove, mv.encode());
    Message m;
    if (!t_->readMessage(m) || m.op != Op::FileOpResult) return false;
    FileOpResultMsg r = FileOpResultMsg::decode(m.payload);
    bool ok = (r.status == FileOpStatus::Ok);
    RP_LOG_INFO("move '" + src + "' -> '" + dst + "': " + (ok ? "OK" : ("FAILED " + r.message)));
    return ok;
}

// ---------------------------------------------------------------------------
// Interactive viewer
// ---------------------------------------------------------------------------
namespace {
constexpr UINT WM_APP_FRAME = WM_APP + 11;
const wchar_t* kViewerClass = L"RadminProViewer";

struct ViewerState {
    SocketTransport* t = nullptr;
    bool control = false;
    std::atomic<bool> running{true};

    std::mutex mu;
    int w = 0, h = 0, stride = 0;
    Bytes front;          // last complete frame (guarded by mu)
    Bytes pending;        // frame being assembled (reader thread only)
    int pw = 0, ph = 0, pstride = 0;
    std::atomic<int> remoteW{0};
    std::atomic<int> remoteH{0};
    HWND hwnd = nullptr;
};

void sendMouse(SocketTransport* t, ViewerState* st, int cx, int cy, uint32_t action,
               int clientW, int clientH) {
    int rw = st->remoteW.load(), rh = st->remoteH.load();
    if (rw <= 0 || rh <= 0 || clientW <= 0 || clientH <= 0) return;
    int rx = std::clamp(cx * rw / clientW, 0, rw - 1);
    int ry = std::clamp(cy * rh / clientH, 0, rh - 1);
    Bytes p;
    putU16(p, static_cast<uint16_t>(rx));
    putU16(p, static_cast<uint16_t>(ry));
    putU32(p, action);
    t->writeMessage(Op::InputMouse, p);
}

LRESULT CALLBACK viewerProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    auto* st = reinterpret_cast<ViewerState*>(GetWindowLongPtrW(hwnd, GWLP_USERDATA));
    switch (msg) {
        case WM_NCCREATE: {
            auto* cs = reinterpret_cast<CREATESTRUCTW*>(lp);
            SetWindowLongPtrW(hwnd, GWLP_USERDATA,
                              reinterpret_cast<LONG_PTR>(cs->lpCreateParams));
            return DefWindowProcW(hwnd, msg, wp, lp);
        }
        case WM_APP_FRAME:
            InvalidateRect(hwnd, nullptr, FALSE);
            return 0;
        case WM_PAINT: {
            PAINTSTRUCT ps;
            HDC dc = BeginPaint(hwnd, &ps);
            RECT rc;
            GetClientRect(hwnd, &rc);
            int cw = rc.right - rc.left, ch = rc.bottom - rc.top;
            if (st) {
                std::lock_guard<std::mutex> lk(st->mu);
                if (!st->front.empty() && st->w > 0 && st->h > 0) {
                    BITMAPINFO bmi{};
                    bmi.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
                    bmi.bmiHeader.biWidth = st->w;
                    bmi.bmiHeader.biHeight = -st->h; // top-down BGRA
                    bmi.bmiHeader.biPlanes = 1;
                    bmi.bmiHeader.biBitCount = 32;
                    bmi.bmiHeader.biCompression = BI_RGB;
                    SetStretchBltMode(dc, HALFTONE);
                    StretchDIBits(dc, 0, 0, cw, ch, 0, 0, st->w, st->h, st->front.data(),
                                  &bmi, DIB_RGB_COLORS, SRCCOPY);
                }
            }
            EndPaint(hwnd, &ps);
            return 0;
        }
        case WM_MOUSEMOVE:
        case WM_LBUTTONDOWN:
        case WM_LBUTTONUP:
        case WM_RBUTTONDOWN:
        case WM_RBUTTONUP: {
            if (st && st->control) {
                RECT rc;
                GetClientRect(hwnd, &rc);
                uint32_t action = 0;
                if (msg == WM_LBUTTONDOWN) action = 1;
                else if (msg == WM_LBUTTONUP) action = 2;
                else if (msg == WM_RBUTTONDOWN) action = 3;
                else if (msg == WM_RBUTTONUP) action = 4;
                sendMouse(st->t, st, GET_X_LPARAM(lp), GET_Y_LPARAM(lp), action,
                          rc.right - rc.left, rc.bottom - rc.top);
            }
            return 0;
        }
        case WM_KEYDOWN:
        case WM_KEYUP: {
            if (st && st->control) {
                Bytes p;
                putU8(p, msg == WM_KEYDOWN ? 1 : 0);
                putU16(p, static_cast<uint16_t>(wp));
                st->t->writeMessage(Op::InputKey, p);
            }
            return 0;
        }
        case WM_DESTROY:
            PostQuitMessage(0);
            return 0;
        default:
            return DefWindowProcW(hwnd, msg, wp, lp);
    }
}

// Reader thread: assemble frames and notify the UI thread.
void readerLoop(ViewerState* st) {
    Message m;
    while (st->running.load() && st->t->readMessage(m)) {
        switch (m.op) {
            case Op::FrameInfo: {
                FrameInfoMsg fi = FrameInfoMsg::decode(m.payload);
                st->pw = fi.width;
                st->ph = fi.height;
                st->pstride = static_cast<int>(fi.stride);
                st->pending.assign(static_cast<size_t>(st->pstride) * st->ph, 0);
                st->remoteW.store(fi.width);
                st->remoteH.store(fi.height);
                break;
            }
            case Op::FrameData: {
                FrameDataMsg fd = FrameDataMsg::decode(m.payload);
                if (fd.offset + fd.data.size() <= st->pending.size()) {
                    std::copy(fd.data.begin(), fd.data.end(),
                              st->pending.begin() + fd.offset);
                }
                break;
            }
            case Op::FrameRect: {
                // Delta tile: blit into the persistent framebuffer at (x,y).
                FrameRectMsg fr = FrameRectMsg::decode(m.payload);
                if (st->pstride > 0 && fr.w > 0 && fr.h > 0) {
                    const size_t rowBytes = static_cast<size_t>(fr.w) * 4;
                    for (uint32_t r = 0; r < fr.h; ++r) {
                        const size_t dst = static_cast<size_t>(fr.y + r) * st->pstride +
                                           static_cast<size_t>(fr.x) * 4;
                        const size_t src = static_cast<size_t>(r) * rowBytes;
                        if (dst + rowBytes <= st->pending.size() &&
                            src + rowBytes <= fr.pixels.size()) {
                            std::memcpy(st->pending.data() + dst, fr.pixels.data() + src,
                                        rowBytes);
                        }
                    }
                }
                break;
            }
            case Op::FrameEnd: {
                {
                    std::lock_guard<std::mutex> lk(st->mu);
                    st->front = st->pending;
                    st->w = st->pw;
                    st->h = st->ph;
                    st->stride = st->pstride;
                }
                if (st->hwnd) PostMessageW(st->hwnd, WM_APP_FRAME, 0, 0);
                break;
            }
            case Op::Bye:
            case Op::Error:
                st->running.store(false);
                if (st->hwnd) PostMessageW(st->hwnd, WM_CLOSE, 0, 0);
                return;
            default:
                break;
        }
    }
    st->running.store(false);
    if (st->hwnd) PostMessageW(st->hwnd, WM_CLOSE, 0, 0);
}

} // namespace

int ClientApp::runViewer() {
    ViewerState st;
    st.t = t_.get();
    st.control = (cfg_.mode == ConnectionMode::FullControl);

    HINSTANCE hinst = GetModuleHandleW(nullptr);
    WNDCLASSEXW wc{};
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = viewerProc;
    wc.hInstance = hinst;
    wc.lpszClassName = kViewerClass;
    wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    wc.hbrBackground = reinterpret_cast<HBRUSH>(GetStockObject(BLACK_BRUSH));
    RegisterClassExW(&wc);

    std::wstring title = L"radminpro viewer - ";
    title += st.control ? L"Full Control" : L"View Only";

    HWND hwnd = CreateWindowExW(0, kViewerClass, title.c_str(), WS_OVERLAPPEDWINDOW,
                                CW_USEDEFAULT, CW_USEDEFAULT, 1024, 640, nullptr, nullptr,
                                hinst, &st);
    if (!hwnd) {
        RP_LOG_ERROR("could not create viewer window");
        return 1;
    }
    st.hwnd = hwnd;
    ShowWindow(hwnd, SW_SHOW);

    std::thread reader(readerLoop, &st);

    MSG msg;
    while (GetMessageW(&msg, nullptr, 0, 0) > 0) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    // Tear down: closing the transport unblocks the reader's blocking
    // readMessage. We deliberately do NOT writeMessage here - that would race
    // with the reader still inside SSL_read on the same SSL object.
    st.running.store(false);
    t_->close();
    if (reader.joinable()) reader.join();
    return 0;
}

} // namespace rp
