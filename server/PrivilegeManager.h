#pragma once
//
// PrivilegeManager.h - least-privilege helper.
//
// Design: the server process runs as a STANDARD user. It never holds admin/
// SYSTEM rights for the steady-state work (screen capture, file transfer in the
// user's own folders). When a genuinely privileged action is requested (e.g.
// remote shutdown, service control), it is executed by spawning a separate
// elevated process via the UAC "runas" verb - scoped to that one task and
// surfaced to the local user as a consent prompt.
//
#include <string>

namespace rp {

class PrivilegeManager {
public:
    // True if the current process token is elevated (full admin token).
    static bool isElevated();

    // True if the user is a member of the local Administrators group (whether
    // or not the current token is elevated).
    static bool isUserInAdminGroup();

    // Full path to the current executable.
    static std::wstring selfPath();

    // Run a command elevated (UAC consent), wait for it, return its exit code.
    // Returns -1 if the user declined or launch failed. Use this ONLY for the
    // specific admin task that requires it - not to elevate the whole server.
    static int runElevated(const std::wstring& exePath, const std::wstring& args);

    // Example privileged task: remote shutdown/restart via the elevated path.
    // Returns true if the elevated command was launched and exited 0.
    static bool requestShutdown(bool restart, unsigned timeoutSeconds = 30);
};

} // namespace rp
