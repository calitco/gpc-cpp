#include "net_common.h"

#include <unistd.h>

namespace gp::net {

bool parse_request_head(int fd, ParsedRequest& out, std::size_t header_limit) {
    std::string buf;
    buf.reserve(1024);
    char tmp[512];
    // Read until end of headers or limit.
    while (buf.find("\r\n\r\n") == std::string::npos) {
        if (buf.size() > header_limit)
            return false;  // oversized headers
        ssize_t n = ::recv(fd, tmp, sizeof(tmp), 0);
        if (n <= 0)
            return false;  // timeout or closed
        buf.append(tmp, static_cast<std::size_t>(n));
    }

    // Request line: METHOD SP PATH SP HTTP/1.x
    auto eol = buf.find("\r\n");
    std::string head = buf.substr(0, eol);
    auto sp1 = head.find(' ');
    auto sp2 = head.rfind(' ');
    if (sp1 == std::string::npos || sp2 == sp1)
        return false;
    out.method = head.substr(0, sp1);
    out.path = head.substr(sp1 + 1, sp2 - sp1 - 1);

    // Preserve anything already received after the headers (usually the body).
    auto hsep = buf.find("\r\n\r\n");
    if (hsep != std::string::npos)
        out.extra = buf.substr(hsep + 4);

    auto lower = [](const std::string& s) {
        std::string r = s;
        for (auto& c : r)
            c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        return r;
    };
    // Headers: name lowercased, value trimmed, wire order preserved.
    out.headers.clear();
    size_t line_start = eol + 2;
    while (line_start < hsep) {
        size_t line_end = buf.find("\r\n", line_start);
        if (line_end == std::string::npos || line_end > hsep)
            break;
        std::string line = buf.substr(line_start, line_end - line_start);
        auto colon = line.find(':');
        if (colon != std::string::npos) {
            size_t vs = colon + 1;
            while (vs < line.size() && line[vs] == ' ')
                ++vs;
            size_t ve = line.find_last_not_of(" \t");
            std::string val =
                (ve != std::string::npos && ve >= vs) ? line.substr(vs, ve - vs + 1) : "";
            out.headers.emplace_back(lower(line.substr(0, colon)), std::move(val));
        }
        line_start = line_end + 2;
    }

    // Content-Length header (case-insensitive).
    out.content_length = 0;
    for (const auto& h : out.headers) {
        if (h.first != "content-length")
            continue;
        for (char c : h.second) {
            if (c < '0' || c > '9')
                return false;  // malformed
            out.content_length = out.content_length * 10 + static_cast<std::size_t>(c - '0');
        }
        break;
    }
    return true;
}

bool read_body(int fd, std::string& body, std::size_t limit, const std::string& extra) {
    body = extra;  // consume bytes already pulled from the socket
    if (body.size() > limit)
        return false;  // more data than declared: reject
    char tmp[4096];
    while (body.size() < limit) {
        ssize_t n = ::recv(fd, tmp, sizeof(tmp), 0);
        if (n <= 0)
            return false;
        body.append(tmp, static_cast<std::size_t>(n));
    }
    return true;
}

}  // namespace gp::net
