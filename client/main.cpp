// radmin_client entry point.
//
// Usage:
//   radmin_client view     <host> --user U [--pass P] --pin HEX [--control] [--port N]
//   radmin_client upload   <host> <local> <remote> --user U --pin HEX [--pass P]
//   radmin_client download <host> <remote> <local> --user U --pin HEX [--pass P]
//   radmin_client delete   <host> <remote>          --user U --pin HEX [--pass P]
//   radmin_client move     <host> <src> <dst>       --user U --pin HEX [--pass P]
//
// Auth uses --pin <sha256-of-server-cert> for self-signed LAN servers, or
// --ca <file> for managed PKI. If --pass is omitted you are prompted (no echo).
//
#include "client/ClientApp.h"
#include "common/Logger.h"
#include "ui/ConnectDialog.h"

#include <windows.h>

#include <cstdlib>
#include <iostream>
#include <map>
#include <string>
#include <vector>

namespace {

struct Args {
    std::string sub;
    std::vector<std::string> pos;
    std::map<std::string, std::string> opt;
    bool control = false;
};

Args parseArgs(int argc, char** argv) {
    Args a;
    if (argc >= 2) a.sub = argv[1];
    for (int i = 2; i < argc; ++i) {
        std::string t = argv[i];
        if (t == "--control") {
            a.control = true;
        } else if (t.rfind("--", 0) == 0) {
            std::string key = t.substr(2);
            if (i + 1 < argc) a.opt[key] = argv[++i];
            else a.opt[key] = "";
        } else {
            a.pos.push_back(t);
        }
    }
    return a;
}

std::string promptPasswordNoEcho() {
    std::cout << "Password (hidden): " << std::flush;
    HANDLE h = GetStdHandle(STD_INPUT_HANDLE);
    DWORD mode = 0;
    GetConsoleMode(h, &mode);
    SetConsoleMode(h, mode & ~ENABLE_ECHO_INPUT);
    std::string pw;
    std::getline(std::cin, pw);
    SetConsoleMode(h, mode);
    std::cout << "\n";
    return pw;
}

uint16_t optU16(const std::map<std::string, std::string>& o, const std::string& k, uint16_t def) {
    auto it = o.find(k);
    if (it == o.end() || it->second.empty()) return def;
    return static_cast<uint16_t>(std::atoi(it->second.c_str()));
}
std::string optStr(const std::map<std::string, std::string>& o, const std::string& k) {
    auto it = o.find(k);
    return it == o.end() ? std::string() : it->second;
}

void usage() {
    std::cerr <<
        "radmin_client <command> <host> [args] --user U --pin HEX [--pass P] [--port N] [--ca F]\n"
        "  view     <host>                 [--control]\n"
        "  upload   <host> <local> <remote>\n"
        "  download <host> <remote> <local>\n"
        "  delete   <host> <remote>\n"
        "  move     <host> <src> <dst>\n";
}

} // namespace

int main(int argc, char** argv) {
    // Zero-args launch (e.g. double-click) -> Connect dialog -> viewer.
    if (argc < 2) {
        auto cfg = rp::showConnectDialog();
        if (!cfg) return 0; // user cancelled
        rp::ClientApp app(std::move(*cfg));
        if (!app.connectAndAuth()) return 2;
        return app.runViewer();
    }

    Args a = parseArgs(argc, argv);
    if (a.sub.empty() || a.pos.empty()) {
        usage();
        return 1;
    }

    rp::ClientConfig cfg;
    cfg.host = a.pos[0];
    cfg.port = optU16(a.opt, "port", 4899);
    cfg.username = optStr(a.opt, "user");
    cfg.pinSha256Hex = optStr(a.opt, "pin");
    cfg.caPath = optStr(a.opt, "ca");
    cfg.password = optStr(a.opt, "pass");
    if (cfg.password.empty()) cfg.password = promptPasswordNoEcho();

    if (cfg.username.empty()) {
        std::cerr << "missing --user\n";
        return 1;
    }

    if (a.sub == "view") {
        cfg.mode = a.control ? rp::ConnectionMode::FullControl : rp::ConnectionMode::ViewOnly;
        rp::ClientApp app(std::move(cfg));
        if (!app.connectAndAuth()) return 2;
        return app.runViewer();
    }

    // All file operations run in FileOnly mode (no video on the wire).
    cfg.mode = rp::ConnectionMode::FileOnly;

    if (a.sub == "upload") {
        if (a.pos.size() < 3) { usage(); return 1; }
        std::string local = a.pos[1], remote = a.pos[2];
        rp::ClientApp app(std::move(cfg));
        if (!app.connectAndAuth()) return 2;
        return app.uploadFile(local, remote) ? 0 : 1;
    }
    if (a.sub == "download") {
        if (a.pos.size() < 3) { usage(); return 1; }
        std::string remote = a.pos[1], local = a.pos[2];
        rp::ClientApp app(std::move(cfg));
        if (!app.connectAndAuth()) return 2;
        return app.downloadFile(remote, local) ? 0 : 1;
    }
    if (a.sub == "delete") {
        if (a.pos.size() < 2) { usage(); return 1; }
        std::string remote = a.pos[1];
        rp::ClientApp app(std::move(cfg));
        if (!app.connectAndAuth()) return 2;
        return app.deleteRemote(remote) ? 0 : 1;
    }
    if (a.sub == "move") {
        if (a.pos.size() < 3) { usage(); return 1; }
        std::string src = a.pos[1], dst = a.pos[2];
        rp::ClientApp app(std::move(cfg));
        if (!app.connectAndAuth()) return 2;
        return app.moveRemote(src, dst) ? 0 : 1;
    }

    usage();
    return 1;
}
