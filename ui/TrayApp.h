#pragma once
//
// TrayApp - the server's main GUI loop. A hidden window owns a system-tray
// icon; right-click pops Options / Users / About / Exit. Options/Users edits
// re-seal the config to disk and hot-restart the underlying ServerApp.
//
#include "server/ServerApp.h"

#include <atomic>
#include <memory>
#include <string>
#include <thread>

namespace rp {

class TrayApp {
public:
    explicit TrayApp(std::string configPath);
    ~TrayApp();
    TrayApp(const TrayApp&) = delete;
    TrayApp& operator=(const TrayApp&) = delete;

    // Blocks running the Win32 message loop. Returns the exit code.
    int run();

private:
    // command handlers (UI thread)
    void onOptions();
    void onUsers();
    void onAbout();
    void onExit();

    // lifecycle of the worker ServerApp
    void startServer();
    void stopServer();
    void restartServer();

    bool loadConfig();   // reads + decrypts configPath_ into cfg_
    bool saveConfig();   // serializes cfg_ + DPAPI-seals to configPath_
    void updateTooltip();

    // static WndProc indirection
    static long long __stdcall wndProcThunk(void* hwnd, unsigned msg,
                                            unsigned long long wp, long long lp);
    long long handle(unsigned msg, unsigned long long wp, long long lp);

    std::string configPath_;
    ServerConfig cfg_;
    bool cfgLoaded_ = false;

    void* hwnd_ = nullptr;       // HWND (opaque to keep windows.h out of header)
    bool iconAdded_ = false;

    std::unique_ptr<ServerApp> server_;
    std::thread serverThread_;
    std::atomic<bool> running_{false};
};

} // namespace rp
