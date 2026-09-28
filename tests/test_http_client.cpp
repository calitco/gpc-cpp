// Tests for finding M-2 fix: mandatory timeouts + response size caps.
#include <gp/http_client.h>
#include <gp/security_options.h>

#include <functional>
#include <thread>

#include "net_common.h"  // internal helper, exposed for tests
#include "test_framework.h"

using gp::SecurityOptions;

namespace {

// One-shot local HTTP server on an ephemeral loopback port.
struct LocalServer {
    gp::net::TcpListener listener;
    std::thread thread;
    uint16_t port = 0;

    bool start(std::function<void(int)> handler) {
        if (!listener.bind_to("127.0.0.1", 0))
            return false;
        port = listener.port();
        thread = std::thread([this, handler] {
            int cfd = listener.accept_with_timeout(5000);
            if (cfd >= 0) {
                handler(cfd);
                ::close(cfd);
            }
        });
        return true;
    }

    ~LocalServer() {
        listener.close_fd();
        if (thread.joinable())
            thread.join();
    }
};

}  // namespace

TEST(http, get_returns_body_and_status) {
    LocalServer srv;
    CHECK(srv.start([](int cfd) {
        std::string resp =
            "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n"
            "Connection: close\r\n\r\nhello";
        gp::net::send_all(cfd, resp.data(), resp.size());
    }));

    SecurityOptions o;
    gp::http::HttpClient c(o);
    auto r = c.get("http://127.0.0.1:" + std::to_string(srv.port) + "/");
    CHECK(r.ok);
    CHECK_EQ(r.status_code, 200L);
    CHECK_EQ(r.body, std::string("hello"));
}

TEST(http, response_size_cap_aborts_large_bodies) {
    LocalServer srv;
    CHECK(srv.start([](int cfd) {
        // Send a 10 KiB body regardless of client behavior.
        std::string body(10240, 'A');
        std::string resp = "HTTP/1.1 200 OK\r\nContent-Length: " + std::to_string(body.size()) +
                           "\r\n" + "Connection: close\r\n\r\n" + body;
        gp::net::send_all(cfd, resp.data(), resp.size());
    }));

    SecurityOptions o;
    o.max_http_response_bytes = 1024;  // far below the 10 KiB body
    gp::http::HttpClient c(o);
    auto r = c.get("http://127.0.0.1:" + std::to_string(srv.port) + "/");
    CHECK(!r.ok);
    CHECK(r.error.find("size cap") != std::string::npos);
}

TEST(http, total_timeout_fires_on_slow_server) {
    LocalServer srv;
    CHECK(srv.start([](int cfd) {
        // Accept, then stall well past the client's total timeout.
        std::this_thread::sleep_for(std::chrono::seconds(3));
        std::string resp =
            "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n"
            "Connection: close\r\n\r\n";
        gp::net::send_all(cfd, resp.data(), resp.size());
    }));

    SecurityOptions o;
    o.http_total_timeout = std::chrono::seconds(1);
    o.http_connect_timeout = std::chrono::seconds(2);
    gp::http::HttpClient c(o);
    auto t0 = std::chrono::steady_clock::now();
    auto r = c.get("http://127.0.0.1:" + std::to_string(srv.port) + "/");
    auto elapsed = std::chrono::steady_clock::now() - t0;
    CHECK(!r.ok);
    CHECK(r.error.find("timeout") != std::string::npos);
    CHECK(elapsed < std::chrono::seconds(3));  // did NOT wait for the server
}

TEST(http, post_sends_body_and_content_type) {
    LocalServer srv;
    CHECK(srv.start([](int cfd) {
        // Read headers + exactly Content-Length body bytes (NOT until EOF: the
        // client keeps the connection open while waiting for the response).
        gp::net::ParsedRequest req;
        if (!gp::net::parse_request_head(cfd, req, 8192))
            return;
        std::string body;
        if (req.content_length > 0)
            gp::net::read_body(cfd, body, req.content_length, req.extra);
        std::string resp = "HTTP/1.1 200 OK\r\nContent-Length: " + std::to_string(body.size()) +
                           "\r\n" + "Connection: close\r\n\r\n" + body;
        gp::net::send_all(cfd, resp.data(), resp.size());
    }));

    SecurityOptions o;
    gp::http::HttpClient c(o);
    auto r = c.post("http://127.0.0.1:" + std::to_string(srv.port) + "/submit",
                    "user=alice&ticket=xyz-123");
    CHECK(r.ok);
    CHECK_EQ(r.status_code, 200L);
    CHECK_EQ(r.body, std::string("user=alice&ticket=xyz-123"));
}

int main() {
    return gp::test::Registry::instance().run_all();
}
