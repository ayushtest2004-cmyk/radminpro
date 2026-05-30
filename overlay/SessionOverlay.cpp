#include "overlay/SessionOverlay.h"

#include <windows.h>

#include <chrono>

namespace rp {

namespace {
constexpr UINT WM_OVL_UPDATE = WM_APP + 1;
constexpr UINT WM_OVL_CLOSE  = WM_APP + 2;
constexpr int  kWidth = 480;
constexpr int  kHeight = 46;
const wchar_t* kClassName = L"RadminProSessionOverlay";
} // namespace

std::string SessionOverlay::caption() {
    std::lock_guard<std::mutex> lk(mu_);
    return caption_;
}

SessionOverlay::~SessionOverlay() { hide(); }

long long __stdcall SessionOverlay::wndProc(void* hWnd, unsigned msg,
                                            unsigned long long wp, long long lp) {
    HWND hwnd = static_cast<HWND>(hWnd);
    auto* self = reinterpret_cast<SessionOverlay*>(GetWindowLongPtrW(hwnd, GWLP_USERDATA));

    switch (msg) {
        case WM_NCCREATE: {
            auto* cs = reinterpret_cast<CREATESTRUCTW*>(lp);
            SetWindowLongPtrW(hwnd, GWLP_USERDATA,
                              reinterpret_cast<LONG_PTR>(cs->lpCreateParams));
            return DefWindowProcW(hwnd, msg, wp, lp);
        }
        case WM_NCHITTEST:
            return HTTRANSPARENT; // mouse passes through

        case WM_TIMER:
            if (self) self->blinkOn_ = !self->blinkOn_;
            InvalidateRect(hwnd, nullptr, FALSE);
            return 0;

        case WM_OVL_UPDATE:
            InvalidateRect(hwnd, nullptr, FALSE);
            return 0;

        case WM_OVL_CLOSE:
            DestroyWindow(hwnd);
            return 0;

        case WM_PAINT: {
            PAINTSTRUCT ps;
            HDC dc = BeginPaint(hwnd, &ps);
            RECT rc;
            GetClientRect(hwnd, &rc);

            HBRUSH bg = CreateSolidBrush(RGB(24, 24, 28));
            FillRect(dc, &rc, bg);
            DeleteObject(bg);

            const bool on = self ? self->blinkOn_ : true;
            HBRUSH dot = CreateSolidBrush(on ? RGB(225, 45, 45) : RGB(95, 30, 30));
            HBRUSH oldBrush = static_cast<HBRUSH>(SelectObject(dc, dot));
            HPEN oldPen = static_cast<HPEN>(SelectObject(dc, GetStockObject(NULL_PEN)));
            int cy = (rc.bottom - rc.top) / 2;
            Ellipse(dc, 16, cy - 7, 30, cy + 7);
            SelectObject(dc, oldBrush);
            SelectObject(dc, oldPen);
            DeleteObject(dot);

            SetBkMode(dc, TRANSPARENT);
            SetTextColor(dc, RGB(240, 240, 240));
            HFONT font = CreateFontW(20, 0, 0, 0, FW_SEMIBOLD, FALSE, FALSE, FALSE,
                                     DEFAULT_CHARSET, OUT_DEFAULT_PRECIS,
                                     CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
                                     DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");
            HFONT oldFont = static_cast<HFONT>(SelectObject(dc, font));
            std::string cap = self ? self->caption() : std::string("Remote session active");
            RECT tr = rc;
            tr.left = 42;
            tr.right -= 10;
            DrawTextA(dc, cap.c_str(), static_cast<int>(cap.size()), &tr,
                      DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS | DT_LEFT);
            SelectObject(dc, oldFont);
            DeleteObject(font);

            EndPaint(hwnd, &ps);
            return 0;
        }

        case WM_DESTROY:
            KillTimer(hwnd, 1);
            PostQuitMessage(0);
            return 0;

        default:
            return DefWindowProcW(hwnd, msg, wp, lp);
    }
}

void SessionOverlay::threadMain() {
    HINSTANCE hinst = GetModuleHandleW(nullptr);

    WNDCLASSEXW wc{};
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = reinterpret_cast<WNDPROC>(&SessionOverlay::wndProc);
    wc.hInstance = hinst;
    wc.lpszClassName = kClassName;
    wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    RegisterClassExW(&wc); // harmless if already registered

    int sx = GetSystemMetrics(SM_CXSCREEN);
    int x = (sx - kWidth) / 2;
    if (x < 0) x = 0;
    int y = 8;

    HWND hwnd = CreateWindowExW(
        WS_EX_LAYERED | WS_EX_TRANSPARENT | WS_EX_TOPMOST | WS_EX_NOACTIVATE |
            WS_EX_TOOLWINDOW,
        kClassName, L"", WS_POPUP, x, y, kWidth, kHeight, nullptr, nullptr, hinst, this);
    if (!hwnd) {
        running_.store(false);
        return;
    }

    SetLayeredWindowAttributes(hwnd, 0, 235, LWA_ALPHA);
    HRGN rgn = CreateRoundRectRgn(0, 0, kWidth + 1, kHeight + 1, 18, 18);
    SetWindowRgn(hwnd, rgn, TRUE); // window takes ownership of the region
    SetTimer(hwnd, 1, 600, nullptr);
    SetWindowPos(hwnd, HWND_TOPMOST, x, y, kWidth, kHeight,
                 SWP_NOACTIVATE | SWP_SHOWWINDOW);

    {
        std::lock_guard<std::mutex> lk(mu_);
        hwnd_ = hwnd;
    }
    running_.store(true);

    MSG msg;
    while (GetMessageW(&msg, nullptr, 0, 0) > 0) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    {
        std::lock_guard<std::mutex> lk(mu_);
        hwnd_ = nullptr;
    }
    running_.store(false);
}

void SessionOverlay::show(const std::string& caption) {
    {
        std::lock_guard<std::mutex> lk(mu_);
        caption_ = caption;
    }
    if (running_.load()) {
        updateText(caption);
        return;
    }
    if (thread_.joinable()) thread_.join(); // reap a previous run
    thread_ = std::thread(&SessionOverlay::threadMain, this);

    // Wait briefly for the UI thread to publish its HWND.
    for (int i = 0; i < 200 && !running_.load(); ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
}

void SessionOverlay::updateText(const std::string& caption) {
    HWND hwnd;
    {
        std::lock_guard<std::mutex> lk(mu_);
        caption_ = caption;
        hwnd = static_cast<HWND>(hwnd_);
    }
    if (hwnd) PostMessageW(hwnd, WM_OVL_UPDATE, 0, 0);
}

void SessionOverlay::hide() {
    HWND hwnd;
    {
        std::lock_guard<std::mutex> lk(mu_);
        hwnd = static_cast<HWND>(hwnd_);
    }
    if (hwnd) PostMessageW(hwnd, WM_OVL_CLOSE, 0, 0);
    if (thread_.joinable()) thread_.join();
}

} // namespace rp
