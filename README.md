# radminpro

A lightweight, **security-first LAN remote-desktop** tool (server/client) for Windows,
written in modern C++17. It is modeled on the Radmin "Full Control / View Only +
per-user rights + IP filtering" model, but built to enterprise security standards:
TLS 1.3, Argon2id credentials, DPAPI-sealed config, subnet allow-listing,
tamper-evident audit logging, a mandatory on-screen session indicator, and a
hash-verified file-transfer protocol.

> **Status:** modular, compile-ready scaffold. Every security control is fully
> implemented. The video path sends a keyframe followed by **tile-based delta
> updates** (only changed 128px tiles, uncompressed BGRA); a real codec
> (H.264/NVENC) is the next bandwidth step — see *Limitations*.
>
> **Build verification:** the authoring environment had no Windows C++ toolchain
> (no MSVC/SDK/CMake/vcpkg, non-admin), so the build is verified by **CI**
> (`.github/workflows/ci.yml`) on `windows-latest` with MSVC + vcpkg, which
> configures, compiles Release, and runs the unit tests (`ctest`). Follow the
> same steps locally (below).

---

## Architecture

The defining design rule: **the Security Manager is isolated from the Video
Streamer.** Crypto, auth, ACL and the peer allow-list live in `rp_security` and
nothing in the media/transport path can bypass them.

```
                        +------------------------+
                        |     SecurityManager     |  rp_security
   peer IP  ─pre-TLS──▶ |  SubnetFilter (CIDR)    |
                        |  TlsContext (TLS 1.3)   |
   user/pass ──────────▶|  PasswordStore (Argon2) |
                        |  DpapiSecret (at-rest)  |
                        +-----------▲------------+
                                    │ rights / verdicts
   +-----------+   +----------+     │      +-------------+   +-------------+
   |  Client   |◀─▶| rp_net   |◀────┴─────▶|  ServerApp  |──▶| rp_media    |
   | (viewer / |   | TLS+TCP  | encrypted  | (sessions)  |   | ScreenCap   |
   |  files)   |   | framing  |  frames    |             |──▶| VideoStream |
   +-----------+   +----------+            |             |   | Overlay     |
                                           |             |   +-------------+
                                           |             |──▶ AuditLogger (rp_audit)
                                           +-------------+──▶ PrivilegeManager
```

| Library / dir   | Responsibility                                                        |
|-----------------|-----------------------------------------------------------------------|
| `common/`       | wire protocol, framing, SHA-256/CSPRNG/secure-wipe, tile frame-diff, logger |
| `security/`     | TLS 1.3 context, Argon2id, DPAPI, CIDR filter, the SecurityManager    |
| `audit/`        | append-only, hash-chained, ACL-locked compliance CSV                  |
| `video/`        | DXGI Desktop Duplication capture + frame streamer                     |
| `overlay/`      | always-on-top "session active" indicator                             |
| `net/`          | WinSock2 listener/connector + OpenSSL framed message channel          |
| `server/`       | accept loop, session state machine, file ops, least-privilege escalation |
| `client/`       | viewer (GDI render + input forwarding) and file-transfer transactions |

---

## Prerequisites

- **Windows 10/11** (DXGI Desktop Duplication; TLS 1.3 via OpenSSL).
- **Visual Studio 2022 Build Tools** (MSVC v143, "Desktop development with C++").
- **CMake ≥ 3.21** and **Ninja**.
- **vcpkg** with `VCPKG_ROOT` set in the environment.
- Dependencies (auto-fetched by vcpkg via `vcpkg.json`): **OpenSSL 3.x**, **argon2**.

> Edit `vcpkg.json` and replace `builtin-baseline` with a real vcpkg baseline
> commit (`git -C %VCPKG_ROOT% rev-parse HEAD`).

## Build

From an **x64 Native Tools Command Prompt for VS**:

```bat
set VCPKG_ROOT=C:\path\to\vcpkg
cmake --preset vcpkg
cmake --build build --config Release
```

Binaries land in `build\Release\radmin_server.exe` and `build\Release\radmin_client.exe`.

## Configure & run

```bat
:: 1. Generate the server TLS cert + key, note the SHA-256 fingerprint
powershell -ExecutionPolicy Bypass -File scripts\gen-cert.ps1 -Cn radmin-host -HostIp 192.168.1.50

:: 2. Create an Argon2id hash for each user
radmin_server --hash-password

:: 3. Copy the template, paste the hashes, set allow_subnets + cert paths
copy config\server.config.example server.config
notepad server.config

:: 4. Seal the config with DPAPI and delete the plaintext
radmin_server --seal-config server.config server.config.enc
del server.config

:: 5. Run the server (standard user; it escalates per-task via UAC)
radmin_server server.config.enc
```

Client (from the operator machine on the same LAN):

```bat
:: View only
radmin_client view 192.168.1.50 --user admin --pin <SHA256_FROM_STEP_1>

:: Full control (mouse/keyboard)
radmin_client view 192.168.1.50 --user admin --pin <FP> --control

:: File transfer (hash-verified, audited)
radmin_client upload   192.168.1.50 .\report.xlsx reports\report.xlsx --user admin --pin <FP>
radmin_client download 192.168.1.50 reports\report.xlsx .\copy.xlsx     --user admin --pin <FP>
radmin_client move     192.168.1.50 reports\a.txt reports\b.txt          --user admin --pin <FP>
radmin_client delete   192.168.1.50 reports\b.txt                        --user admin --pin <FP>
```

`--pass` may be supplied on the command line; if omitted the client prompts
without echo.

---

## Tests & CI

A dependency-free assertion harness (`tests/test_main.cpp`, run via `ctest`)
covers the security-critical logic: SHA-256 vectors, hex/byte round-trips, every
protocol message's encode/decode, the rights model, the CIDR subnet filter
(IPv4 + IPv6, fail-closed, malformed-input rejection), Argon2id hash/verify
(incl. per-hash salt uniqueness), DPAPI seal/unseal (incl. wrong-entropy
rejection), and **audit hash-chain integrity** (including a tamper-detection
case that mutates a historical row and asserts the chain breaks).

```bat
ctest --test-dir build -C Release --output-on-failure
```

CI runs configure + Release build + tests on every push.

## File-transfer transaction (integrity-checked)

Upload, exactly as specified:

1. **Request** — client sends `FileUploadReq{ remotePath, size, sha256 }`.
2. **Verify perms** — server checks the `FileTransfer` right and that the
   resolved path stays inside `file_root` (path-traversal rejected).
3. **Transfer** — data flows as `FileBlock` chunks **inside the TLS tunnel**.
4. **Verify integrity** — on `FileComplete` the server recomputes SHA-256 and
   compares to the client's claim. Only on a match is the temp file atomically
   renamed into place; a mismatch is discarded and logged as `INTEGRITY_FAIL`.

Download mirrors this with the client doing the final hash check and returning a
signed-off `FileVerify` receipt for the audit trail.

---

## Audit log

CSV at `audit_csv`, columns:

```
timestamp_utc, pid, actor, peer, action, target, result, detail, chain
```

- **Append-only** and written with RFC-4180 quoting.
- **Tamper-evident:** `chain = SHA256(previous_chain || row)`. Editing or
  deleting any historical row breaks every subsequent `chain` value, which an
  auditor can detect by recomputing the chain.
- The file is created with a **restrictive DACL** (SYSTEM + Administrators only).
- Logged actions: connection accept/reject, auth success/failure, session
  start/end, file upload/download/move/delete, integrity failure, permission
  denied.

---

## Compliance checklist (IT deployment)

| Requirement              | How radminpro meets it |
|--------------------------|------------------------|
| **Data at rest**         | Server config (incl. Argon2 hashes) sealed with **DPAPI** (`--seal-config`, `CryptProtectData`, machine scope). Private key ACL-restricted by `gen-cert.ps1`. |
| **Data in transit**      | **TLS 1.3** preferred, **TLS 1.2 floor**; SSLv2/3, TLS 1.0/1.1, compression and renegotiation hard-disabled; AEAD-only cipher policy (`security/TlsContext.cpp`). |
| **Identity management**  | Self-defined **local** users with **Argon2id** salted hashes + per-user rights + per-account lockout. Optional mutual-TLS (`client_ca`) for certificate-based client identity. No Active Directory dependency — local accounts by design (sufficient for a small LAN). |
| **Integrity**            | File transfers SHA-256 verified end-to-end; audit log hash-chained. **Code-sign** both EXEs with your Authenticode cert before distribution (see below). |
| **Least privilege**      | Server runs as a **standard user**; privileged actions (e.g. shutdown) are delegated to a short-lived **elevated** process via UAC (`server/PrivilegeManager.cpp`). It warns if started elevated. |
| **Anti-tampering**       | **Subnet allow-list** (CIDR), fail-closed, enforced **before** TLS. |
| **No covert monitoring** | A mandatory always-on-top, click-through **session overlay** shows the remote user + IP for the entire session. |

### Code signing (do this before deployment)

```bat
signtool sign /fd SHA256 /tr http://timestamp.digicert.com /td SHA256 ^
  /a build\Release\radmin_server.exe build\Release\radmin_client.exe
```

---

## Security model & limitations

- **Pin or PKI, never blind trust.** The client refuses to connect unless you
  pass `--pin <sha256>` (self-signed LAN) or `--ca <bundle>` (managed PKI).
- **Run the server as a standard user.** It only needs your session's desktop to
  capture and inject input; it escalates narrowly and transiently for admin tasks.
- **Single reader per connection.** Each session is serviced by one thread, so a
  single `SSL` object is never used concurrently; `writeMessage` is additionally
  mutex-guarded for the client's viewer (reader thread + UI thread).
- **Not yet production-grade:**
  - Video ships uncompressed BGRA tiles (keyframe + changed-tile deltas). For
    lower bandwidth add a real codec (H.264/NVENC); tiles could also be driven
    by DXGI dirty/move rects. Multi-monitor selection is single-output today.
  - File uploads/downloads buffer the whole file in memory; stream large files.
  - A Windows **service** wrapper and clipboard/audio channels are not built.
    (Concurrent-session caps + a handshake timeout *are* in place.)
  - Input injection requires the server to run in the interactive desktop
    session; it cannot drive the secure desktop (UAC/login screens).

## Layout

```
CMakeLists.txt  CMakePresets.json  vcpkg.json
common/   security/   audit/   video/   overlay/   net/   server/   client/
tests/test_main.cpp               .github/workflows/ci.yml
config/server.config.example      scripts/gen-cert.ps1
```
