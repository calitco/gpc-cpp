// Internal POSIX socket helpers shared by AuthServer and CallbackListener.
#pragma once

#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstdint>
#include <cstring>
#include <string>
#include <utility>
#include <vector>

namespace gp::net {

class TcpListener {
   public:
    TcpListener() = default;
    ~TcpListener() { close_fd(); }
    TcpListener(const TcpListener&) = delete;
    TcpListener& operator=(const TcpListener&) = delete;

    // Bind to addr:port (port 0 = ephemeral). Returns false on error.
    bool bind_to(const std::string& addr, uint16_t port) {
        close_fd();
        fd_ = ::socket(AF_INET, SOCK_STREAM, 0);
        if (fd_ < 0)
            return false;
        int one = 1;
        setsockopt(fd_, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
        sockaddr_in sa{};
        sa.sin_family = AF_INET;
        sa.sin_port = htons(port);
        if (::inet_pton(AF_INET, addr.c_str(), &sa.sin_addr) != 1)
            return false;
        if (::bind(fd_, reinterpret_cast<sockaddr*>(&sa), sizeof(sa)) != 0)
            return false;
        if (::listen(fd_, 8) != 0)
            return false;
        sockaddr_in bound{};
        socklen_t slen = sizeof(bound);
        if (::getsockname(fd_, reinterpret_cast<sockaddr*>(&bound), &slen) == 0)
            port_ = ntohs(bound.sin_port);
        return true;
    }

    // Accept with a deadline (ms). Returns -1 on timeout/error.
    int accept_with_timeout(int timeout_ms) {
        if (fd_ < 0)
            return -1;
        pollfd pfd{fd_, POLLIN, 0};
        if (::poll(&pfd, 1, timeout_ms) <= 0)
            return -1;
        return ::accept(fd_, nullptr, nullptr);
    }

    uint16_t port() const { return port_; }
    int fd() const { return fd_; }
    void close_fd() {
        if (fd_ >= 0) {
            ::close(fd_);
            fd_ = -1;
        }
    }

    // True only for loopback addresses (127.0.0.0/8). Anything else —
    // including 0.0.0.0 and LAN IPs — requires the explicit opt-in switch.
    static bool is_loopback(const std::string& addr) { return addr.rfind("127.", 0) == 0; }

   private:
    int fd_ = -1;
    uint16_t port_ = 0;
};

// Set a receive timeout on an accepted socket (guards against slowloris).
inline void set_recv_timeout(int fd, int ms) {
    timeval tv{ms / 1000, (ms % 1000) * 1000};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
}

// Read exactly up to `limit` bytes of a request: headers + optional body.
// Returns false on timeout/error/oversize. Fills method, path, and body.
struct ParsedRequest {
    std::string method;
    std::string path;
    std::size_t content_length = 0;
    // Headers as (lowercased-name, trimmed-value) pairs, in wire order.
    std::vector<std::pair<std::string, std::string>> headers;
    // Bytes received beyond the header terminator (often the whole body, since
    // clients send request+body in one segment). MUST be consumed before any
    // further recv() — data read from the socket cannot be re-read.
    std::string extra;
};

bool parse_request_head(int fd, ParsedRequest& out, std::size_t header_limit);

// Read a body of exactly `limit` bytes (caller must ensure the declared
// length is <= cap). `extra` holds any body bytes already received by
// parse_request_head and is consumed first.
bool read_body(int fd, std::string& body, std::size_t limit, const std::string& extra = "");

inline void send_all(int fd, const char* data, std::size_t len) {
    std::size_t off = 0;
    while (off < len) {
        ssize_t n = ::send(fd, data + off, len - off, MSG_NOSIGNAL);
        if (n <= 0)
            return;
        off += static_cast<std::size_t>(n);
    }
}

inline void send_response_ext(int fd, const std::string& status_line, const std::string& body,
                              const std::string& content_type,
                              const std::vector<std::string>& extra_headers) {
    std::string resp = "HTTP/1.1 " + status_line + "\r\n";
    for (const auto& h : extra_headers)
        resp += h + "\r\n";
    resp += "Content-Type: " + content_type + "\r\n" +
            "Content-Length: " + std::to_string(body.size()) + "\r\n" +
            "Connection: close\r\n\r\n" + body;
    send_all(fd, resp.data(), resp.size());
}

inline void send_response(int fd, const std::string& status_line, const std::string& body,
                          const std::string& content_type = "text/plain") {
    send_response_ext(fd, status_line, body, content_type, {});
}

}  // namespace gp::net
