#pragma once
//
// SessionOverlay.h - mandatory "you are being viewed" indicator.
//
// While a remote session is live, a small always-on-top, click-through banner
// is shown on the host's screen (top-center) with a blinking red dot and the
// remote user/IP. This makes covert/"hidden" monitoring impossible by design -
// a privacy and anti-abuse control, not a cosmetic feature.
//
// The banner runs on its own UI thread with a dedicated message loop so it
// never blocks the capture/network path.
//
#include <atomic>
#include <mutex>
#include <string>
#include <thread>

namespace rp {

class SessionOverlay {
public:
    SessionOverlay() = default;
    ~SessionOverlay();
    SessionOverlay(const SessionOverlay&) = delete;
    SessionOverlay& operator=(const SessionOverlay&) = delete;

    // Show (or update) the banner with the given caption. Idempotent.
    void show(const std::string& caption);

    // Update the caption while shown.
    void updateText(const std::string& caption);

    // Hide and tear down the banner.
    void hide();

    bool visible() const { return running_.load(); }

private:
    void threadMain();
    std::string caption();
    static long long __stdcall wndProc(void* hwnd, unsigned msg, unsigned long long wp,
                                       long long lp);

    std::thread thread_;
    std::atomic<bool> running_{false};
    void* hwnd_ = nullptr; // HWND, posted to from other threads
    std::string caption_;
    std::mutex mu_;
    bool blinkOn_ = true; // UI-thread only
};

} // namespace rp
