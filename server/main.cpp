// radmin_server entry point.
//
// Usage:
//   radmin_server <config>                 run the server (config may be .enc)
//   radmin_server --hash-password          read a password (no echo) -> Argon2id
//   radmin_server --seal-config <in> <out> DPAPI-encrypt a plaintext config
//
#include "common/Logger.h"
#include "common/Util.h"
#include "security/DpapiSecret.h"
#include "security/PasswordStore.h"
#include "server/ServerApp.h"
#include "ui/TrayApp.h"

#include <windows.h>

#include <cstdio>
#include <fstream>
#include <iostream>
#include <iterator>
#include <sstream>
#include <string>

namespace {
rp::ServerApp* g_app = nullptr;

BOOL WINAPI ctrlHandler(DWORD type) {
    if (type == CTRL_C_EVENT || type == CTRL_CLOSE_EVENT || type == CTRL_BREAK_EVENT) {
        RP_LOG_INFO("shutdown requested");
        if (g_app) g_app->stop();
        return TRUE;
    }
    return FALSE;
}

std::string readFileText(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) throw std::runtime_error("cannot open " + path);
    std::ostringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

rp::Bytes readFileBytes(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) throw std::runtime_error("cannot open " + path);
    return rp::Bytes((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
}

int cmdHashPassword() {
    std::cout << "Enter password to hash (input hidden): " << std::flush;
    HANDLE h = GetStdHandle(STD_INPUT_HANDLE);
    DWORD mode = 0;
    GetConsoleMode(h, &mode);
    SetConsoleMode(h, mode & ~ENABLE_ECHO_INPUT);
    std::string pw;
    std::getline(std::cin, pw);
    SetConsoleMode(h, mode);
    std::cout << "\n";

    if (pw.empty()) {
        std::cerr << "empty password rejected\n";
        return 1;
    }
    std::string encoded = rp::PasswordStore::hash(std::move(pw));
    std::cout << "Argon2id hash (paste into config as user.<name>.hash):\n"
              << encoded << "\n";
    return 0;
}

int cmdSealConfig(const std::string& in, const std::string& out) {
    std::string text = readFileText(in);
    rp::Bytes enc = rp::DpapiSecret::protectString(text, rp::DpapiSecret::Scope::LocalMachine);
    rp::secureZero(text);
    std::ofstream f(out, std::ios::binary | std::ios::trunc);
    if (!f) {
        std::cerr << "cannot write " << out << "\n";
        return 1;
    }
    f.write(reinterpret_cast<const char*>(enc.data()),
            static_cast<std::streamsize>(enc.size()));
    std::cout << "Sealed config written to " << out
              << ". Securely delete the plaintext '" << in << "'.\n";
    return 0;
}

bool endsWith(const std::string& s, const std::string& suf) {
    return s.size() >= suf.size() && s.compare(s.size() - suf.size(), suf.size(), suf) == 0;
}

} // namespace

int main(int argc, char** argv) {
    if (argc >= 2 && std::string(argv[1]) == "--hash-password") {
        return cmdHashPassword();
    }
    if (argc >= 4 && std::string(argv[1]) == "--seal-config") {
        try {
            return cmdSealConfig(argv[2], argv[3]);
        } catch (const std::exception& e) {
            std::cerr << "seal-config failed: " << e.what() << "\n";
            return 1;
        }
    }
    // No args -> GUI / tray mode. Default config sits next to the exe.
    if (argc < 2) {
        wchar_t exePath[MAX_PATH];
        DWORD n = GetModuleFileNameW(nullptr, exePath, MAX_PATH);
        if (n) {
            wchar_t* slash = wcsrchr(exePath, L'\\');
            if (slash) { *slash = L'\0'; SetCurrentDirectoryW(exePath); }
        }
        rp::TrayApp app("server.config.enc");
        return app.run();
    }

    const std::string configPath = argv[1];
    std::string text;
    try {
        if (endsWith(configPath, ".enc")) {
            rp::Bytes blob = readFileBytes(configPath);
            text = rp::DpapiSecret::unprotectToString(blob); // data-at-rest decrypt
        } else {
            RP_LOG_WARN("loading PLAINTEXT config; production should use a "
                        "DPAPI-sealed .enc (see --seal-config)");
            text = readFileText(configPath);
        }
    } catch (const std::exception& e) {
        std::cerr << "config load failed: " << e.what() << "\n";
        return 1;
    }

    rp::ServerConfig cfg = rp::ServerConfig::parse(text);
    rp::secureZero(text); // config held the credential hashes

    rp::ServerApp app(std::move(cfg));
    g_app = &app;
    SetConsoleCtrlHandler(ctrlHandler, TRUE);

    int rc = app.run();
    g_app = nullptr;
    return rc;
}
