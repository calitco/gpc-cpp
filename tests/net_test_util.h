// Test helpers: minimal blocking HTTP client over raw sockets.
#pragma once

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <string>

namespace gp::testnet {

inline int connect_tcp(const std::string& host, uint16_t port) {
    int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
        return -1;
    sockaddr_in sa{};
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    if (::inet_pton(AF_INET, host.c_str(), &sa.sin_addr) != 1) {
        ::close(fd);
        return -1;
    }
    if (::connect(fd, reinterpret_cast<sockaddr*>(&sa), sizeof(sa)) != 0) {
        ::close(fd);
        return -1;
    }
    return fd;
}

// Send a request and read the full response until close. Returns the raw
// response (status line + headers + body). Empty string on error.
inline std::string http_roundtrip(const std::string& host, uint16_t port, const std::string& method,
                                  const std::string& path, const std::string& body = "") {
    int fd = connect_tcp(host, port);
    if (fd < 0)
        return "";
    std::string req = method + " " + path + " HTTP/1.1\r\n" + "Host: " + host + "\r\n" +
                      "Content-Length: " + std::to_string(body.size()) + "\r\n" +
                      "Connection: close\r\n\r\n" + body;
    const char* p = req.data();
    std::size_t off = 0;
    while (off < req.size()) {
        ssize_t n = ::send(fd, p + off, req.size() - off, MSG_NOSIGNAL);
        if (n <= 0) {
            ::close(fd);
            return "";
        }
        off += static_cast<std::size_t>(n);
    }
    std::string resp;
    char tmp[4096];
    while (true) {
        ssize_t n = ::recv(fd, tmp, sizeof(tmp), 0);
        if (n <= 0)
            break;
        resp.append(tmp, static_cast<std::size_t>(n));
    }
    ::close(fd);
    return resp;
}

inline std::string status_of(const std::string& raw_response) {
    auto eol = raw_response.find("\r\n");
    if (eol == std::string::npos)
        return "";
    return raw_response.substr(0, eol);
}

inline std::string body_of(const std::string& raw_response) {
    auto sep = raw_response.find("\r\n\r\n");
    if (sep == std::string::npos)
        return "";
    return raw_response.substr(sep + 4);
}

}  // namespace gp::testnet
