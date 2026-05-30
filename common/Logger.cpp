#include "common/Logger.h"

#include <chrono>
#include <cstdio>
#include <ctime>

namespace rp {

Logger& Logger::instance() {
    static Logger inst;
    return inst;
}

static const char* levelTag(LogLevel l) {
    switch (l) {
        case LogLevel::Debug: return "DEBUG";
        case LogLevel::Info:  return "INFO ";
        case LogLevel::Warn:  return "WARN ";
        case LogLevel::Error: return "ERROR";
    }
    return "?????";
}

void Logger::log(LogLevel lvl, const std::string& msg) {
    if (static_cast<int>(lvl) < static_cast<int>(level_)) return;

    using namespace std::chrono;
    auto now = system_clock::now();
    std::time_t t = system_clock::to_time_t(now);
    std::tm tm{};
    localtime_s(&tm, &t);
    char ts[32];
    std::strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", &tm);

    std::lock_guard<std::mutex> lk(mu_);
    std::fprintf(stderr, "%s [%s] %s: %s\n", ts, levelTag(lvl), component_.c_str(), msg.c_str());
    std::fflush(stderr);
}

} // namespace rp
