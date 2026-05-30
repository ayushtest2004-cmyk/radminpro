#pragma once
//
// Logger.h - operator-facing diagnostic logging. This is NOT the compliance
// audit trail (see audit/AuditLogger.h) - it is for debugging/ops and may be
// noisy. Never log secrets (passwords, keys, password hashes) here.
//
#include <mutex>
#include <string>

namespace rp {

enum class LogLevel { Debug = 0, Info = 1, Warn = 2, Error = 3 };

class Logger {
public:
    static Logger& instance();

    void setLevel(LogLevel lvl) { level_ = lvl; }
    void setComponent(std::string c) { component_ = std::move(c); }

    void log(LogLevel lvl, const std::string& msg);

    void debug(const std::string& m) { log(LogLevel::Debug, m); }
    void info(const std::string& m) { log(LogLevel::Info, m); }
    void warn(const std::string& m) { log(LogLevel::Warn, m); }
    void error(const std::string& m) { log(LogLevel::Error, m); }

private:
    Logger() = default;
    LogLevel level_ = LogLevel::Info;
    std::string component_ = "radminpro";
    std::mutex mu_;
};

} // namespace rp

#define RP_LOG_INFO(msg)  ::rp::Logger::instance().info(msg)
#define RP_LOG_WARN(msg)  ::rp::Logger::instance().warn(msg)
#define RP_LOG_ERROR(msg) ::rp::Logger::instance().error(msg)
#define RP_LOG_DEBUG(msg) ::rp::Logger::instance().debug(msg)
