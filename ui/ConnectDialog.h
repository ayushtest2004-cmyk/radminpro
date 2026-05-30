#pragma once
//
// ConnectDialog - the client-side launcher dialog.
//
// Replaces the CLI for the common path: double-click radmin_client.exe and
// you get a Radmin-style Connect window with host/port/user/pass/pin/mode.
// Returns a populated ClientConfig on OK, std::nullopt on Cancel/close.
//
#include "client/ClientApp.h"

#include <optional>

namespace rp {

std::optional<ClientConfig> showConnectDialog();

} // namespace rp
