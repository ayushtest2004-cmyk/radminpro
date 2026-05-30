#include "audit/AuditLogger.h"

#include "common/Logger.h"
#include "common/Util.h"

#include <windows.h>
#include <aclapi.h>

#include <chrono>
#include <cstdio>
#include <ctime>
#include <stdexcept>
#include <vector>

namespace rp {

const char* auditActionName(AuditAction a) {
    switch (a) {
        case AuditAction::Connection: return "CONNECTION";
        case AuditAction::Rejected: return "REJECTED";
        case AuditAction::AuthSuccess: return "AUTH_SUCCESS";
        case AuditAction::AuthFailure: return "AUTH_FAILURE";
        case AuditAction::SessionStart: return "SESSION_START";
        case AuditAction::SessionEnd: return "SESSION_END";
        case AuditAction::FileUpload: return "FILE_UPLOAD";
        case AuditAction::FileDownload: return "FILE_DOWNLOAD";
        case AuditAction::FileMove: return "FILE_MOVE";
        case AuditAction::FileDelete: return "FILE_DELETE";
        case AuditAction::IntegrityFail: return "INTEGRITY_FAIL";
        case AuditAction::PermissionDenied: return "PERMISSION_DENIED";
        case AuditAction::ConfigChange: return "CONFIG_CHANGE";
        case AuditAction::Error: return "ERROR";
    }
    return "UNKNOWN";
}

namespace {

const char* kHeader =
    "timestamp_utc,pid,actor,peer,action,target,result,detail,chain";

std::wstring widen(const std::string& s) {
    if (s.empty()) return L"";
    int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), nullptr, 0);
    std::wstring w(n, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), &w[0], n);
    return w;
}

// Restrict the audit file to SYSTEM + Administrators + the account the server
// runs as (so a least-privilege standard-user server can still append/resume on
// restart) and protect it from inherited ACEs. Best-effort: returns false if it
// cannot be applied (e.g. non-NTFS volume) rather than blocking logging.
bool applyRestrictiveAcl(const std::string& path) {
    BYTE sysSidBuf[SECURITY_MAX_SID_SIZE];
    BYTE admSidBuf[SECURITY_MAX_SID_SIZE];
    DWORD sysLen = sizeof(sysSidBuf), admLen = sizeof(admSidBuf);
    if (!CreateWellKnownSid(WinLocalSystemSid, nullptr, sysSidBuf, &sysLen) ||
        !CreateWellKnownSid(WinBuiltinAdministratorsSid, nullptr, admSidBuf, &admLen)) {
        return false;
    }

    // Current user's SID (kept alive in userBuf until SetEntriesInAcl copies it).
    HANDLE token = nullptr;
    std::vector<BYTE> userBuf;
    PSID userSid = nullptr;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
        DWORD need = 0;
        GetTokenInformation(token, TokenUser, nullptr, 0, &need);
        if (need) {
            userBuf.resize(need);
            if (GetTokenInformation(token, TokenUser, userBuf.data(), need, &need)) {
                userSid = reinterpret_cast<TOKEN_USER*>(userBuf.data())->User.Sid;
            }
        }
        CloseHandle(token);
    }

    EXPLICIT_ACCESSW ea[3] = {};
    int n = 0;
    auto addAce = [&](PSID sid, TRUSTEE_TYPE trusteeType) {
        ea[n].grfAccessPermissions = GENERIC_ALL;
        ea[n].grfAccessMode = GRANT_ACCESS;
        ea[n].grfInheritance = NO_INHERITANCE;
        ea[n].Trustee.TrusteeForm = TRUSTEE_IS_SID;
        ea[n].Trustee.TrusteeType = trusteeType;
        ea[n].Trustee.ptstrName = reinterpret_cast<LPWSTR>(sid);
        ++n;
    };
    addAce(sysSidBuf, TRUSTEE_IS_USER);
    addAce(admSidBuf, TRUSTEE_IS_GROUP);
    if (userSid) addAce(userSid, TRUSTEE_IS_USER);

    PACL acl = nullptr;
    if (SetEntriesInAclW(static_cast<ULONG>(n), ea, nullptr, &acl) != ERROR_SUCCESS) {
        return false;
    }

    std::wstring wpath = widen(path);
    DWORD rc = SetNamedSecurityInfoW(
        &wpath[0], SE_FILE_OBJECT,
        DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
        nullptr, nullptr, acl, nullptr);
    if (acl) LocalFree(acl);
    return rc == ERROR_SUCCESS;
}

std::string lastCsvField(const std::string& line) {
    auto pos = line.find_last_of(',');
    std::string f = (pos == std::string::npos) ? line : line.substr(pos + 1);
    while (!f.empty() && (f.back() == '\r' || f.back() == '\n' || f.back() == ' '))
        f.pop_back();
    return f;
}

} // namespace

AuditLogger::AuditLogger(std::string csvPath) : path_(std::move(csvPath)) {
    bool existedNonEmpty = false;
    {
        std::ifstream probe(path_, std::ios::binary | std::ios::ate);
        existedNonEmpty = probe.good() && probe.tellg() > 0;
    }

    out_.open(path_, std::ios::out | std::ios::app | std::ios::binary);
    if (!out_.is_open()) {
        throw std::runtime_error("AuditLogger: cannot open '" + path_ + "'");
    }

    if (!existedNonEmpty) {
        out_ << kHeader << "\r\n";
        out_.flush();
        prevChainHex_ = std::string(64, '0'); // genesis
        if (!applyRestrictiveAcl(path_)) {
            RP_LOG_WARN("audit: could not apply restrictive ACL to " + path_);
        }
    } else {
        resumeChain();
    }
}

void AuditLogger::resumeChain() {
    std::ifstream in(path_, std::ios::binary);
    std::string line, last;
    while (std::getline(in, line)) {
        if (!line.empty() && line != "\r") last = line;
    }
    // If we only ever saw the header, last is the header -> seed genesis.
    if (last.empty() || last.rfind("timestamp_utc,", 0) == 0) {
        prevChainHex_ = std::string(64, '0');
    } else {
        prevChainHex_ = lastCsvField(last);
        if (prevChainHex_.size() != 64) prevChainHex_ = std::string(64, '0');
    }
}

std::string AuditLogger::utcTimestamp() {
    using namespace std::chrono;
    auto now = system_clock::now();
    auto ms = duration_cast<milliseconds>(now.time_since_epoch()) % 1000;
    std::time_t t = system_clock::to_time_t(now);
    std::tm tm{};
    gmtime_s(&tm, &t);
    char buf[32];
    std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%S", &tm);
    char out[40];
    std::snprintf(out, sizeof(out), "%s.%03dZ", buf, static_cast<int>(ms.count()));
    return out;
}

std::string AuditLogger::csvEscape(const std::string& field) {
    bool needQuote = field.find_first_of(",\"\r\n") != std::string::npos;
    if (!needQuote) return field;
    std::string out = "\"";
    for (char c : field) {
        if (c == '"') out += "\"\""; // double the quote
        else out += c;
    }
    out += "\"";
    return out;
}

void AuditLogger::log(const AuditEvent& ev) {
    std::lock_guard<std::mutex> lk(mu_);

    std::string row;
    row += csvEscape(utcTimestamp()); row += ",";
    row += std::to_string(GetCurrentProcessId()); row += ",";
    row += csvEscape(ev.actor.empty() ? "-" : ev.actor); row += ",";
    row += csvEscape(ev.peer.empty() ? "-" : ev.peer); row += ",";
    row += csvEscape(auditActionName(ev.action)); row += ",";
    row += csvEscape(ev.target); row += ",";
    row += csvEscape(ev.result); row += ",";
    row += csvEscape(ev.detail);

    // chain = sha256(prevChainHex || row-so-far)
    std::string chainInput = prevChainHex_ + row;
    std::string chain = toHex(sha256(reinterpret_cast<const uint8_t*>(chainInput.data()),
                                     chainInput.size()));

    out_ << row << "," << chain << "\r\n";
    out_.flush();
    prevChainHex_ = chain;
}

void AuditLogger::connection(const std::string& peer, bool accepted, const std::string& detail) {
    log({"-", peer, accepted ? AuditAction::Connection : AuditAction::Rejected, "",
         accepted ? "OK" : "DENIED", detail});
}

void AuditLogger::auth(const std::string& actor, const std::string& peer, bool ok,
                       const std::string& detail) {
    log({actor, peer, ok ? AuditAction::AuthSuccess : AuditAction::AuthFailure, "",
         ok ? "OK" : "FAIL", detail});
}

void AuditLogger::session(const std::string& actor, const std::string& peer, bool start,
                          const std::string& detail) {
    log({actor, peer, start ? AuditAction::SessionStart : AuditAction::SessionEnd, "", "OK",
         detail});
}

void AuditLogger::fileOp(AuditAction action, const std::string& actor, const std::string& peer,
                         const std::string& target, const std::string& result,
                         const std::string& detail) {
    log({actor, peer, action, target, result, detail});
}

} // namespace rp
