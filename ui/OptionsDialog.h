#pragma once
//
// OptionsDialog - the server-side settings dialog (tab control with General /
// IP Filter / Logging). Reads `cfg` and writes back into it on OK.
//
#include "server/ServerApp.h"

#include <windows.h>

namespace rp {

// Returns true if the user clicked OK and `cfg` has been mutated, false on
// Cancel/close.
bool showOptionsDialog(HWND owner, ServerConfig& cfg);

} // namespace rp
