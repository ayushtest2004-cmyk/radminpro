#include "ui/TrayApp.h"

#include "common/Logger.h"
#include "common/Util.h"
#include "security/DpapiSecret.h"
#include "ui/OptionsDialog.h"
#include "ui/UsersDialog.h"
#include "ui/WinUtil.h"
#include "ui/resource.h"

#include <windows.h>
#include <objbase.h>     // CoInitializeEx / CoUninitialize / COINIT_*
#include <shellapi.h>
#include <commctrl.h>

#include <fstream>
#include <iterator>
#include <sstream>

namespace rp {

namespace {

const wchar_t* kClassName  = L"RadminProTray";
constexpr UINT WM_TRAY_CB  = WM_APP + 10; // Shell_NotifyIcon callback
constexpr UINT_PTR kTrayId = 1;

INT_PTR CALLBACK aboutProc(HWND dlg, UINT msg, WPARAM wp, LPARAM /*lp*/) {
    switch (msg) {
        case WM_INITDIALOG:
            winutil::centerDialog(dlg);
            return TRUE;
        case WM_COMMAND:
            if (LOWORD(wp) == IDOK || LOWORD(wp) == IDCANCEL) {
                EndDialog(dlg, IDOK);
                return TRUE;
            }
            break;
        case WM_CLOSE:
            EndDialog(dlg, IDCANCEL);
            return TRUE;
    }
    return FALSE;
}

std::string readFileText(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) throw std::runtime_error("cannot open " + path);
    std::ostringstream ss; ss << f.rdbuf();
    return ss.str();
}
Bytes readFileBytes(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) throw std::runtime_error("cannot open " + path);
    return Bytes((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
}
bool endsWith(const std::string& s, const std::string& suf) {
    return s.size() >= suf.size() && s.compare(s.size() - suf.size(), suf.size(), suf) == 0;
}

} // namespace

TrayApp::TrayApp(std::string configPath) : configPath_(std::move(configPath)) {}

TrayApp::~TrayApp() {
    stopServer();
    if (iconAdded_) {
        NOTIFYICONDATAW nid{};
        nid.cbSize = sizeof(nid);
        nid.hWnd = static_cast<HWND>(hwnd_);
        nid.uID  = kTrayId;
        Shell_NotifyIconW(NIM_DELETE, &nid);
    }
}

bool TrayApp::loadConfig() {
    try {
        std::string text;
        if (endsWith(configPath_, ".enc")) {
            Bytes blob = readFileBytes(configPath_);
            text = DpapiSecret::unprotectToString(blob);
        } else {
            text = readFileText(configPath_);
        }
        cfg_ = ServerConfig::parse(text);
        secureZero(text);
        cfgLoaded_ = true;
        return true;
    } catch (const std::exception& e) {
        RP_LOG_WARN(std::string("config load failed: ") + e.what());
        cfgLoaded_ = false;
        return false;
    }
}

bool TrayApp::saveConfig() {
    try {
        std::string text = ServerApp::serialize(cfg_);
        if (endsWith(configPath_, ".enc")) {
            Bytes enc = DpapiSecret::protectString(text, DpapiSecret::Scope::LocalMachine);
            secureZero(text);
            std::ofstream f(configPath_, std::ios::binary | std::ios::trunc);
            if (!f) throw std::runtime_error("cannot write " + configPath_);
            f.write(reinterpret_cast<const char*>(enc.data()),
                    static_cast<std::streamsize>(enc.size()));
        } else {
            std::ofstream f(configPath_, std::ios::binary | std::ios::trunc);
            if (!f) throw std::runtime_error("cannot write " + configPath_);
            f.write(text.data(), static_cast<std::streamsize>(text.size()));
            secureZero(text);
        }
        return true;
    } catch (const std::exception& e) {
        winutil::messageBoxError(static_cast<HWND>(hwnd_),
            std::string("Failed to save config: ") + e.what());
        return false;
    }
}

void TrayApp::startServer() {
    if (server_) return;
    if (!cfgLoaded_) {
        updateTooltip();
        return;
    }
    server_ = std::make_unique<ServerApp>(cfg_);
    ServerApp* s = server_.get();
    running_.store(true);
    serverThread_ = std::thread([s, this]() {
        int rc = s->run();
        running_.store(false);
        RP_LOG_INFO("server thread exited rc=" + std::to_string(rc));
    });
    Sleep(150); // let it bind before we update tip
    updateTooltip();
}

void TrayApp::stopServer() {
    if (!server_) return;
    server_->stop();
    if (serverThread_.joinable()) serverThread_.join();
    server_.reset();
    running_.store(false);
    updateTooltip();
}

void TrayApp::restartServer() { stopServer(); startServer(); }

void TrayApp::updateTooltip() {
    if (!iconAdded_) return;
    NOTIFYICONDATAW nid{};
    nid.cbSize = sizeof(nid);
    nid.hWnd   = static_cast<HWND>(hwnd_);
    nid.uID    = kTrayId;
    nid.uFlags = NIF_TIP;
    std::wstring tip;
    if (!cfgLoaded_) {
        tip = L"radminpro - no config loaded (right-click -> Options)";
    } else if (!running_.load()) {
        tip = L"radminpro - stopped";
    } else {
        tip = L"radminpro - listening on " + winutil::widen(cfg_.bindAddr) + L":" +
              std::to_wstring(cfg_.port);
    }
    lstrcpynW(nid.szTip, tip.c_str(), ARRAYSIZE(nid.szTip));
    Shell_NotifyIconW(NIM_MODIFY, &nid);
}

// -------------------------------------------------------------------------
// command handlers
// -------------------------------------------------------------------------
void TrayApp::onOptions() {
    if (!cfgLoaded_) {
        // First-time setup: start with sane defaults so the dialog has something.
        cfg_ = ServerConfig{};
        cfg_.allowSubnets = "192.168.1.0/24";
    }
    if (!showOptionsDialog(static_cast<HWND>(hwnd_), cfg_)) return;
    if (saveConfig()) {
        cfgLoaded_ = true;
        restartServer();
        winutil::messageBoxInfo(static_cast<HWND>(hwnd_),
            "Settings saved and server restarted.");
    }
}

void TrayApp::onUsers() {
    if (!cfgLoaded_) {
        winutil::messageBoxError(static_cast<HWND>(hwnd_),
            "Configure server Options first (Options menu).");
        return;
    }
    if (!showUsersDialog(static_cast<HWND>(hwnd_), cfg_)) return;
    if (saveConfig()) {
        restartServer();
        winutil::messageBoxInfo(static_cast<HWND>(hwnd_),
            "Users updated and server restarted.");
    }
}

void TrayApp::onAbout() {
    HINSTANCE hi = GetModuleHandleW(nullptr);
    DialogBoxParamW(hi, MAKEINTRESOURCEW(IDD_ABOUT), static_cast<HWND>(hwnd_),
                    aboutProc, 0);
}

void TrayApp::onExit() {
    PostMessageW(static_cast<HWND>(hwnd_), WM_CLOSE, 0, 0);
}

// -------------------------------------------------------------------------
// WndProc
// -------------------------------------------------------------------------
long long __stdcall TrayApp::wndProcThunk(void* hwnd, unsigned msg,
                                          unsigned long long wp, long long lp) {
    if (msg == WM_NCCREATE) {
        auto* cs = reinterpret_cast<CREATESTRUCTW*>(lp);
        SetWindowLongPtrW(static_cast<HWND>(hwnd), GWLP_USERDATA,
                          reinterpret_cast<LONG_PTR>(cs->lpCreateParams));
        return DefWindowProcW(static_cast<HWND>(hwnd), msg, wp, lp);
    }
    auto* self = reinterpret_cast<TrayApp*>(
        GetWindowLongPtrW(static_cast<HWND>(hwnd), GWLP_USERDATA));
    if (self) return self->handle(msg, wp, lp);
    return DefWindowProcW(static_cast<HWND>(hwnd), msg, wp, lp);
}

long long TrayApp::handle(unsigned msg, unsigned long long wp, long long lp) {
    HWND hwnd = static_cast<HWND>(hwnd_);
    switch (msg) {
        case WM_TRAY_CB: {
            const UINT ev = LOWORD(lp);
            if (ev == WM_RBUTTONUP || ev == WM_CONTEXTMENU) {
                POINT pt; GetCursorPos(&pt);
                HINSTANCE hi = GetModuleHandleW(nullptr);
                HMENU root = LoadMenuW(hi, MAKEINTRESOURCEW(IDR_TRAY_MENU));
                HMENU pop  = GetSubMenu(root, 0);
                SetForegroundWindow(hwnd); // recommended before TrackPopupMenu
                TrackPopupMenu(pop, TPM_RIGHTBUTTON | TPM_BOTTOMALIGN,
                               pt.x, pt.y, 0, hwnd, nullptr);
                PostMessageW(hwnd, WM_NULL, 0, 0); // dismiss menu reliably
                DestroyMenu(root);
            } else if (ev == WM_LBUTTONDBLCLK) {
                onOptions();
            }
            return 0;
        }
        case WM_COMMAND: {
            switch (LOWORD(wp)) {
                case IDM_TRAY_OPTIONS: onOptions(); return 0;
                case IDM_TRAY_USERS:   onUsers();   return 0;
                case IDM_TRAY_ABOUT:   onAbout();   return 0;
                case IDM_TRAY_EXIT:    onExit();    return 0;
            }
            break;
        }
        case WM_CLOSE:
            DestroyWindow(hwnd);
            return 0;
        case WM_DESTROY:
            PostQuitMessage(0);
            return 0;
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}

// -------------------------------------------------------------------------
// run
// -------------------------------------------------------------------------
int TrayApp::run() {
    CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED); // for SHBrowseForFolder
    INITCOMMONCONTROLSEX icc{sizeof(icc),
        ICC_STANDARD_CLASSES | ICC_TAB_CLASSES | ICC_LISTVIEW_CLASSES | ICC_BAR_CLASSES};
    InitCommonControlsEx(&icc);

    HINSTANCE hi = GetModuleHandleW(nullptr);

    WNDCLASSEXW wc{};
    wc.cbSize        = sizeof(wc);
    wc.lpfnWndProc   = reinterpret_cast<WNDPROC>(&TrayApp::wndProcThunk);
    wc.hInstance     = hi;
    wc.lpszClassName = kClassName;
    wc.hIcon         = LoadIconW(nullptr, IDI_APPLICATION);
    wc.hCursor       = LoadCursorW(nullptr, IDC_ARROW);
    RegisterClassExW(&wc);

    HWND h = CreateWindowExW(0, kClassName, L"radminpro", WS_OVERLAPPED,
                             0, 0, 0, 0, HWND_MESSAGE, nullptr, hi, this);
    if (!h) {
        // HWND_MESSAGE windows can't host popup menus on some configs; fall back
        // to a normal hidden top-level window.
        h = CreateWindowExW(0, kClassName, L"radminpro", WS_OVERLAPPED,
                            0, 0, 1, 1, nullptr, nullptr, hi, this);
        if (!h) return 1;
    }
    hwnd_ = h;

    // Tray icon
    NOTIFYICONDATAW nid{};
    nid.cbSize           = sizeof(nid);
    nid.hWnd             = h;
    nid.uID              = kTrayId;
    nid.uFlags           = NIF_MESSAGE | NIF_ICON | NIF_TIP;
    nid.uCallbackMessage = WM_TRAY_CB;
    nid.hIcon            = LoadIconW(nullptr, IDI_INFORMATION);
    lstrcpynW(nid.szTip, L"radminpro - starting...", ARRAYSIZE(nid.szTip));
    if (Shell_NotifyIconW(NIM_ADD, &nid)) iconAdded_ = true;

    // Try to load + start the server with whatever config is on disk.
    if (loadConfig()) {
        startServer();
    } else {
        winutil::messageBoxInfo(h,
            "No usable config at '" + configPath_ +
            "'.\nRight-click the tray icon -> Options to set one up.");
    }

    MSG msg;
    while (GetMessageW(&msg, nullptr, 0, 0) > 0) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    stopServer();
    CoUninitialize();
    return 0;
}

} // namespace rp
