#include "server/PrivilegeManager.h"

#include "common/Logger.h"

#include <windows.h>
#include <shellapi.h>

namespace rp {

bool PrivilegeManager::isElevated() {
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) return false;
    TOKEN_ELEVATION elev{};
    DWORD sz = sizeof(elev);
    bool elevated = false;
    if (GetTokenInformation(token, TokenElevation, &elev, sizeof(elev), &sz)) {
        elevated = elev.TokenIsElevated != 0;
    }
    CloseHandle(token);
    return elevated;
}

bool PrivilegeManager::isUserInAdminGroup() {
    SID_IDENTIFIER_AUTHORITY nt = SECURITY_NT_AUTHORITY;
    PSID adminGroup = nullptr;
    if (!AllocateAndInitializeSid(&nt, 2, SECURITY_BUILTIN_DOMAIN_RID,
                                  DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0,
                                  &adminGroup)) {
        return false;
    }
    BOOL isMember = FALSE;
    if (!CheckTokenMembership(nullptr, adminGroup, &isMember)) isMember = FALSE;
    FreeSid(adminGroup);
    return isMember != FALSE;
}

std::wstring PrivilegeManager::selfPath() {
    wchar_t buf[MAX_PATH];
    DWORD n = GetModuleFileNameW(nullptr, buf, MAX_PATH);
    return std::wstring(buf, n);
}

int PrivilegeManager::runElevated(const std::wstring& exePath, const std::wstring& args) {
    SHELLEXECUTEINFOW sei{};
    sei.cbSize = sizeof(sei);
    sei.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_FLAG_NO_UI;
    sei.lpVerb = L"runas"; // triggers UAC elevation prompt
    sei.lpFile = exePath.c_str();
    sei.lpParameters = args.empty() ? nullptr : args.c_str();
    sei.nShow = SW_HIDE;

    if (!ShellExecuteExW(&sei)) {
        DWORD err = GetLastError();
        if (err == ERROR_CANCELLED) {
            RP_LOG_WARN("elevation declined by local user");
        } else {
            RP_LOG_ERROR("ShellExecuteEx(runas) failed: " + std::to_string(err));
        }
        return -1;
    }
    if (!sei.hProcess) return -1;

    WaitForSingleObject(sei.hProcess, INFINITE);
    DWORD code = static_cast<DWORD>(-1);
    GetExitCodeProcess(sei.hProcess, &code);
    CloseHandle(sei.hProcess);
    return static_cast<int>(code);
}

bool PrivilegeManager::requestShutdown(bool restart, unsigned timeoutSeconds) {
    // Delegate to the OS shutdown utility through the elevated path rather than
    // holding SeShutdownPrivilege in the long-running server process.
    std::wstring args = restart ? L"/r" : L"/s";
    args += L" /t " + std::to_wstring(timeoutSeconds) + L" /c \"radminpro remote request\"";
    int rc = runElevated(L"shutdown.exe", args);
    return rc == 0;
}

} // namespace rp
