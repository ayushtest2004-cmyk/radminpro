cmake_minimum_required(VERSION 3.21)

# ---------------------------------------------------------------------------
# radminpro - hardened LAN remote desktop (server/client)
#
# Build (from a "x64 Native Tools" prompt, with VCPKG_ROOT set):
#   cmake --preset vcpkg
#   cmake --build build --config Release
#
# See README.md for the full toolchain + deployment instructions.
# ---------------------------------------------------------------------------

project(radminpro LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT WIN32)
  message(FATAL_ERROR "radminpro targets Windows (DXGI / WinSock2 / DPAPI).")
endif()

if(NOT MSVC)
  message(WARNING "radminpro is developed against MSVC; other compilers are untested.")
endif()

# Hardening + Windows API level (Win10+ for DXGI Desktop Duplication & TLS 1.3).
add_compile_definitions(
  UNICODE _UNICODE
  WIN32_LEAN_AND_MEAN
  NOMINMAX
  _WIN32_WINNT=0x0A00
)

if(MSVC)
  add_compile_options(/W4 /permissive- /EHsc /utf-8)
  # Security-relevant compiler/linker hardening:
  #   /GS         stack buffer-overrun cookies
  #   /guard:cf   Control Flow Guard
  # Linker: CFG, ASLR (/DYNAMICBASE), DEP (/NXCOMPAT), 64-bit ASLR entropy.
  add_compile_options(/GS /guard:cf)
  add_link_options(/guard:cf /DYNAMICBASE /NXCOMPAT /HIGHENTROPYVA)
  # Opt in to /sdl for stricter source hardening once the tree is warning-clean.
endif()

find_package(OpenSSL REQUIRED)                     # OpenSSL::SSL OpenSSL::Crypto
find_package(unofficial-argon2 CONFIG REQUIRED)    # unofficial::argon2::libargon2

# ---------------------------------------------------------------------------
# rp_common - protocol framing, byte/crypto utilities (no policy, no I/O loops)
# ---------------------------------------------------------------------------
add_library(rp_common STATIC
  common/Util.cpp
  common/Protocol.cpp
  common/Logger.cpp
  common/FrameDiff.cpp
)
target_include_directories(rp_common PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(rp_common PUBLIC OpenSSL::Crypto)

# ---------------------------------------------------------------------------
# rp_security - THE Security Manager. Deliberately isolated from media/IO so a
# reviewer can audit the entire trust boundary in one library.
# ---------------------------------------------------------------------------
add_library(rp_security STATIC
  security/PasswordStore.cpp
  security/SubnetFilter.cpp
  security/DpapiSecret.cpp
  security/TlsContext.cpp
  security/SecurityManager.cpp
)
target_link_libraries(rp_security
  PUBLIC  rp_common OpenSSL::SSL OpenSSL::Crypto
  # ws2_32: inet_pton parsing only; crypt32: DPAPI
  PRIVATE unofficial::argon2::libargon2 crypt32 ws2_32
)

# ---------------------------------------------------------------------------
# rp_audit - append-only compliance CSV
# ---------------------------------------------------------------------------
add_library(rp_audit STATIC
  audit/AuditLogger.cpp
)
target_link_libraries(rp_audit PUBLIC rp_common PRIVATE advapi32)

# ---------------------------------------------------------------------------
# rp_media - DXGI capture, frame streamer, on-screen session overlay.
# Completely unaware of auth/crypto policy (separation requirement).
# ---------------------------------------------------------------------------
add_library(rp_media STATIC
  video/ScreenCapture.cpp
  video/VideoStreamer.cpp
  overlay/SessionOverlay.cpp
)
target_link_libraries(rp_media PUBLIC rp_common
  PRIVATE d3d11 dxgi dxguid gdi32 user32
)

# ---------------------------------------------------------------------------
# rp_net - WinSock2 + OpenSSL transport bridge
# ---------------------------------------------------------------------------
add_library(rp_net STATIC
  net/SocketTransport.cpp
)
target_link_libraries(rp_net PUBLIC rp_common rp_security PRIVATE ws2_32)

# ---------------------------------------------------------------------------
# rp_ui - native Win32 dialogs (Connect / Options / Users / Add User / About)
# plus the system-tray app. Each exe also compiles ui/resources.rc directly
# so the dialog templates + manifest end up in the .exe's resource table.
# ---------------------------------------------------------------------------
add_library(rp_ui STATIC
  ui/WinUtil.cpp
  ui/ConnectDialog.cpp
  ui/OptionsDialog.cpp
  ui/UsersDialog.cpp
  ui/TrayApp.cpp
)
target_link_libraries(rp_ui
  PUBLIC  rp_common rp_security rp_audit rp_media rp_net
  PRIVATE user32 gdi32 comctl32 comdlg32 shell32 ole32
)

# ---------------------------------------------------------------------------
# Executables
# ---------------------------------------------------------------------------
# Make sure the RC compiler can find resource.h and radminpro.manifest in ui/.
set_source_files_properties(ui/resources.rc PROPERTIES
  COMPILE_FLAGS "/I\"${CMAKE_CURRENT_SOURCE_DIR}/ui\""
)

add_executable(radmin_server
  server/PrivilegeManager.cpp
  server/ServerApp.cpp
  server/main.cpp
  ui/resources.rc
)
target_link_libraries(radmin_server PRIVATE
  rp_ui rp_net rp_security rp_audit rp_media rp_common
  advapi32 shell32 user32 comctl32 comdlg32
)
# Windows GUI subsystem -> no console window when double-clicked. The CRT entry
# stays mainCRTStartup so int main(argc,argv) still works (and CLI mode behaves
# correctly when launched from a cmd window).
set_target_properties(radmin_server PROPERTIES WIN32_EXECUTABLE TRUE)
# /MANIFEST:NO -> don't let the linker generate its own manifest; ours is
# embedded by the RC file (1 24 "radminpro.manifest"). Two manifests cause
# CVTRES "duplicate resource".
target_link_options(radmin_server PRIVATE "/ENTRY:mainCRTStartup" "/MANIFEST:NO")

add_executable(radmin_client
  client/ClientApp.cpp
  client/main.cpp
  ui/resources.rc
)
target_link_libraries(radmin_client PRIVATE
  rp_ui rp_net rp_security rp_audit rp_media rp_common
  user32 gdi32 comctl32 comdlg32 shell32
)
set_target_properties(radmin_client PROPERTIES WIN32_EXECUTABLE TRUE)
target_link_options(radmin_client PRIVATE "/ENTRY:mainCRTStartup" "/MANIFEST:NO")

install(TARGETS radmin_server radmin_client
  RUNTIME DESTINATION bin
)

# ---------------------------------------------------------------------------
# Tests (ctest). Exercises the pure/security-critical logic without a network.
# ---------------------------------------------------------------------------
enable_testing()
add_executable(rp_tests tests/test_main.cpp)
target_link_libraries(rp_tests PRIVATE rp_security rp_audit rp_common)
add_test(NAME rp_tests COMMAND rp_tests)
