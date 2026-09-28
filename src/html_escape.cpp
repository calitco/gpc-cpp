#include "gp/html_escape.h"

#include <algorithm>
#include <cctype>
#include <cstring>

namespace gp::html {

std::string escape_text(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 8);
    for (char c : s) {
        switch (c) {
            case '&':
                out += "&amp;";
                break;
            case '<':
                out += "&lt;";
                break;
            case '>':
                out += "&gt;";
                break;
            case '"':
                out += "&quot;";
                break;
            case '\'':
                out += "&#39;";
                break;
            default:
                out += c;
                break;
        }
    }
    return out;
}

namespace {
bool host_in_allowlist(const std::string& host_port, const std::vector<std::string>& allowlist) {
    if (allowlist.empty())
        return true;
    // Strip a trailing :port for comparison.
    std::string host = host_port;
    auto colon = host.rfind(':');
    if (colon != std::string::npos)
        host = host.substr(0, colon);
    auto norm = [](std::string s) {
        std::transform(s.begin(), s.end(), s.begin(),
                       [](unsigned char c) { return std::tolower(c); });
        return s;
    };
    const std::string target = norm(host);
    for (const auto& allowed : allowlist) {
        if (target == norm(allowed))
            return true;
    }
    return false;
}
}  // namespace

bool valid_redirect_target(const std::string& url, const std::vector<std::string>& allowlist) {
    // No control characters anywhere: blocks CRLF header injection and the
    // class of malformed-input panics from the Rust original.
    for (unsigned char c : url) {
        if (c < 0x20 || c == 0x7f)
            return false;
    }
    auto is_http = [](const std::string& u, const char* scheme) {
        std::size_t len = std::strlen(scheme);
        if (u.size() <= len + 3)
            return false;  // need "://..."
        if (u.compare(0, len, scheme) != 0)
            return false;
        return u.compare(len, 3, "://") == 0;
    };
    bool https = is_http(url, "https");
    bool http = is_http(url, "http");
    if (!https && !http)
        return false;

    // Extract host: must be non-empty and contain no '/', whitespace or '@'
    // (userinfo would allow credential smuggling into the redirect).
    std::size_t start = url.find("://") + 3;
    std::size_t end = url.find_first_of("/?# ", start);
    std::string host_port =
        (end == std::string::npos) ? url.substr(start) : url.substr(start, end - start);
    if (host_port.empty() || host_port.find('@') != std::string::npos)
        return false;
    for (char c : host_port) {
        if (std::isalnum(static_cast<unsigned char>(c)) || c == '.' || c == '-' || c == ':' ||
            c == '[' || c == ']')
            continue;
        return false;
    }
    return host_in_allowlist(host_port, allowlist);
}

}  // namespace gp::html
