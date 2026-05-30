#pragma once
//
// AuditLogger.h - append-only, tamper-evident compliance CSV.
//
// Every security-relevant action (connection, auth, file move/delete/transfer)
// is written as one CSV row. Properties:
//   * RFC-4180 quoting so paths with commas/quotes/newlines stay one record.
//   * Thread-safe (single mutex; one writer).
//   * Hash-chained: each row carries sha256(prev_chain || row), so deleting or
//     editing any historical row breaks the chain and is detectable on audit.
//   * Best-effort restrictive DACL (SYSTEM + Administrators) on the file.
//
#include <fstream>
#include <mutex>
#include <string>

namespace rp {

enum class AuditAction {
    Connection,     // TCP peer accepted (post subnet filter)
    Rejected,       // peer rejected by subnet filter
    AuthSuccess,
    AuthFailure,
    SessionStart,   // remote control/view session began (overlay shown)
    SessionEnd,
    FileUpload,
    FileDownload,
    FileMove,
    FileDelete,
    IntegrityFail,  // post-transfer hash mismatch
    PermissionDenied,
    ConfigChange,
    Error,
};

const char* auditActionName(AuditAction a);

struct AuditEvent {
    std::string actor;  // authenticated username, or "-"
    std::string peer;   // "ip:port"
    AuditAction action = AuditAction::Error;
    std::string target; // file path / object acted upon
    std::string result; // "OK" / "DENIED" / "MISMATCH" / etc.
    std::string detail; // free-form context
};

class AuditLogger {
public:
    // Opens (creates) the CSV in append mode, writes the header if new, and
    // resumes the hash chain from the last row. Throws std::runtime_error if
    // the file cannot be opened.
    explicit AuditLogger(std::string csvPath);

    void log(const AuditEvent& ev);

    // Convenience wrappers.
    void connection(const std::string& peer, bool accepted, const std::string& detail = "");
    void auth(const std::string& actor, const std::string& peer, bool ok,
              const std::string& detail = "");
    void session(const std::string& actor, const std::string& peer, bool start,
                 const std::string& detail = "");
    void fileOp(AuditAction action, const std::string& actor, const std::string& peer,
                const std::string& target, const std::string& result,
                const std::string& detail = "");

private:
    static std::string csvEscape(const std::string& field);
    static std::string utcTimestamp();
    void resumeChain();

    std::string path_;
    std::ofstream out_;
    std::string prevChainHex_; // last chain value (hex sha256)
    std::mutex mu_;
};

} // namespace rp
