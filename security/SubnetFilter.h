#pragma once
//
// SubnetFilter.h - LAN allow-list (anti-tampering / blast-radius control).
//
// The server refuses any peer whose source IP is not inside one of the
// configured CIDR ranges (e.g. 192.168.1.0/24). This check runs BEFORE the TLS
// handshake so unauthorized networks never even reach the crypto stack. It is a
// defense-in-depth control, not a replacement for authentication.
//
// Supports IPv4 and IPv6 ranges.
//
#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace rp {

class SubnetFilter {
public:
    // Parse "192.168.1.0/24" / "10.0.0.0/8" / "fe80::/10". Returns false if
    // malformed (and the rule is not added).
    bool addCidr(const std::string& cidr);

    // Parse a comma/whitespace separated list; returns count successfully added.
    size_t addList(const std::string& list);

    // Is this textual IP (v4 or v6) inside any configured range?
    // With no rules configured, returns false (fail closed).
    bool isAllowed(const std::string& ip) const;

    bool empty() const { return rules_.empty(); }
    size_t size() const { return rules_.size(); }

private:
    struct Rule {
        int family;                  // AF_INET or AF_INET6
        std::array<uint8_t, 16> net; // network address (masked)
        int prefixBits;
    };
    std::vector<Rule> rules_;

    static bool parseAddr(const std::string& ip, int& family,
                          std::array<uint8_t, 16>& out);
};

} // namespace rp
