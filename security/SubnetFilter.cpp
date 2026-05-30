#include "security/SubnetFilter.h"

#include <winsock2.h>
#include <ws2tcpip.h>

#include <cctype>
#include <cstdlib>
#include <cstring>

namespace rp {

bool SubnetFilter::parseAddr(const std::string& ip, int& family,
                             std::array<uint8_t, 16>& out) {
    out.fill(0);
    in_addr v4{};
    if (InetPtonA(AF_INET, ip.c_str(), &v4) == 1) {
        family = AF_INET;
        std::memcpy(out.data(), &v4, 4);
        return true;
    }
    in6_addr v6{};
    if (InetPtonA(AF_INET6, ip.c_str(), &v6) == 1) {
        family = AF_INET6;
        std::memcpy(out.data(), &v6, 16);
        return true;
    }
    return false;
}

static void maskInPlace(std::array<uint8_t, 16>& a, int family, int prefixBits) {
    int total = (family == AF_INET) ? 32 : 128;
    for (int i = 0; i < (family == AF_INET ? 4 : 16); ++i) {
        int bitStart = i * 8;
        if (bitStart >= prefixBits) {
            a[i] = 0;
        } else if (bitStart + 8 > prefixBits) {
            int keep = prefixBits - bitStart;            // 1..7
            uint8_t mask = static_cast<uint8_t>(0xFF << (8 - keep));
            a[i] &= mask;
        }
    }
    (void)total;
}

static bool matchPrefix(const std::array<uint8_t, 16>& a,
                        const std::array<uint8_t, 16>& net, int prefixBits) {
    int fullBytes = prefixBits / 8;
    int remBits = prefixBits % 8;
    for (int i = 0; i < fullBytes; ++i) {
        if (a[i] != net[i]) return false;
    }
    if (remBits) {
        uint8_t mask = static_cast<uint8_t>(0xFF << (8 - remBits));
        if ((a[fullBytes] & mask) != (net[fullBytes] & mask)) return false;
    }
    return true;
}

bool SubnetFilter::addCidr(const std::string& cidr) {
    std::string addr = cidr;
    int prefix = -1;

    auto slash = cidr.find('/');
    if (slash != std::string::npos) {
        addr = cidr.substr(0, slash);
        const std::string bits = cidr.substr(slash + 1);
        if (bits.empty()) return false;
        for (char c : bits) {
            if (!std::isdigit(static_cast<unsigned char>(c))) return false;
        }
        prefix = std::atoi(bits.c_str());
    }

    int family;
    std::array<uint8_t, 16> a{};
    if (!parseAddr(addr, family, a)) return false;

    int maxPrefix = (family == AF_INET) ? 32 : 128;
    if (prefix < 0) prefix = maxPrefix; // bare host address
    if (prefix > maxPrefix) return false;

    maskInPlace(a, family, prefix);
    rules_.push_back(Rule{family, a, prefix});
    return true;
}

size_t SubnetFilter::addList(const std::string& list) {
    size_t added = 0;
    std::string token;
    auto flush = [&]() {
        if (!token.empty()) {
            if (addCidr(token)) ++added;
            token.clear();
        }
    };
    for (char c : list) {
        if (c == ',' || std::isspace(static_cast<unsigned char>(c))) {
            flush();
        } else {
            token.push_back(c);
        }
    }
    flush();
    return added;
}

bool SubnetFilter::isAllowed(const std::string& ip) const {
    if (rules_.empty()) return false; // fail closed: no allow-list => deny all

    int family;
    std::array<uint8_t, 16> a{};
    if (!parseAddr(ip, family, a)) return false;

    for (const auto& r : rules_) {
        if (r.family != family) continue;
        if (matchPrefix(a, r.net, r.prefixBits)) return true;
    }
    return false;
}

} // namespace rp
