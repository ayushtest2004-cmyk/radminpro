#pragma once
//
// UsersDialog - manage Radmin users + their rights checkboxes. Matches the
// Radmin "Users" reference screenshot. Hashes new passwords in-process via
// PasswordStore (Argon2id) so the plaintext never leaves memory.
//
#include "server/ServerApp.h"

#include <windows.h>

namespace rp {

// Returns true if OK was pressed and `cfg.users` has been replaced with the
// edited working copy; false on Cancel/close.
bool showUsersDialog(HWND owner, ServerConfig& cfg);

} // namespace rp
