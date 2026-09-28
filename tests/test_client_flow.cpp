// Tests for Wave H: the end-to-end client orchestrator (ClientFlow), the
// credential readers, and gpclient CLI parsing. All gateway traffic goes to a
// local loopback fixture server; the tunnel step uses a fake transport.
#include <gp/client_flow.h>
#include <gp/trace.h>
#include <gp/tunnel_client.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <sstream>
#include <thread>

#include "net_common.h"  // internal helper, exposed for tests
#include "net_test_util.h"
#include "test_framework.h"

using gp::SecurityOptions;
using namespace gp::client;
namespace tunnel = gp::tunnel;

namespace {

// ---------------------------------------------------------------------------
// Loopback fixture gateway (prelogin / login / portal / connect / extend)
// ---------------------------------------------------------------------------

std::string http_response(int status, const std::string& body,
                          const std::vector<std::pair<std::string, std::string>>& extra = {}) {
    static const char* reasons[] = {"OK", "Found", "Unauthorized", "Not Found"};
    int idx = status == 200 ? 0 : status == 302 ? 1 : status == 401 ? 2 : 3;
    std::string resp = "HTTP/1.1 " + std::to_string(status) + " " + reasons[idx] + "\r\n";
    for (const auto& h : extra)
        resp += h.first + ": " + h.second + "\r\n";
    resp += "Content-Length: " + std::to_string(body.size()) + "\r\n";
    resp += "Connection: close\r\n\r\n";
    resp += body;
    return resp;
}

std::string read_request(int fd) {
    std::string buf;
    char tmp[4096];
    while (buf.find("\r\n\r\n") == std::string::npos) {
        ssize_t n = ::recv(fd, tmp, sizeof(tmp), 0);
        if (n <= 0)
            return buf;
        buf.append(tmp, static_cast<size_t>(n));
    }
    auto sep = buf.find("\r\n\r\n");
    std::string head = buf.substr(0, sep);
    long content_length = 0;
    size_t line_start = 0;
    while (line_start < head.size()) {
        auto line_end = head.find("\r\n", line_start);
        std::string line = head.substr(line_start, line_end - line_start);
        auto colon = line.find(':');
        if (colon != std::string::npos) {
            std::string name = line.substr(0, colon);
            for (auto& c : name)
                c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
            if (name == "content-length")
                content_length = std::atol(line.c_str() + colon + 1);
        }
        line_start = (line_end == std::string::npos) ? head.size() : line_end + 2;
    }
    long have = static_cast<long>(buf.size() - sep - 4);
    while (have < content_length) {
        ssize_t n = ::recv(fd, tmp, sizeof(tmp), 0);
        if (n <= 0)
            break;
        buf.append(tmp, static_cast<size_t>(n));
        have += n;
    }
    return buf;
}

struct ParsedReq {
    std::string method;
    std::string path;
    std::string body;
};

ParsedReq parse_request(const std::string& raw) {
    ParsedReq r;
    auto sep = raw.find("\r\n\r\n");
    if (sep == std::string::npos)
        return r;
    std::string head = raw.substr(0, sep);
    r.body = raw.substr(sep + 4);
    size_t line_start = 0;
    bool first = true;
    while (line_start < head.size()) {
        auto line_end = head.find("\r\n", line_start);
        std::string line = head.substr(line_start, line_end - line_start);
        if (first) {
            auto sp1 = line.find(' ');
            auto sp2 = line.rfind(' ');
            if (sp1 != std::string::npos && sp2 > sp1) {
                r.method = line.substr(0, sp1);
                r.path = line.substr(sp1 + 1, sp2 - sp1 - 1);
            }
            first = false;
        }
        line_start = (line_end == std::string::npos) ? head.size() : line_end + 2;
    }
    return r;
}

struct GatewayFixture {
    gp::net::TcpListener listener;
    std::thread thread;
    uint16_t port = 0;
    std::mutex mu;
    int total_requests = 0;
    int login_posts = 0;
    int tunnel_posts = 0;  // first POST /tunnel/start = connect, rest = extend
    std::string last_login_body;
    // Login succeeds only when this exact password is present ("" = accept all).
    std::string expected_password;
    // Set by the destructor before close_fd so the serve loop can tell an idle
    // accept timeout apart from a real shutdown and keep serving in between.
    std::atomic<bool> stopping{false};

    GatewayFixture() = default;
    GatewayFixture(const GatewayFixture&) = delete;
    GatewayFixture& operator=(const GatewayFixture&) = delete;

    ~GatewayFixture() {
        stopping.store(true);
        listener.close_fd();  // unblocks the accept loop
        if (thread.joinable())
            thread.join();
    }

    std::string base_url() const { return "http://127.0.0.1:" + std::to_string(port); }

    bool start(int max_requests = 48) {
        if (!listener.bind_to("127.0.0.1", 0))
            return false;
        port = listener.port();
        thread = std::thread([this, max_requests] { serve(max_requests); });
        return true;
    }

    void serve(int max_requests) {
        for (int i = 0; i < max_requests; ++i) {
            int cfd = listener.accept_with_timeout(250);
            if (cfd < 0) {
                if (stopping.load())
                    break;
                continue;  // idle gap between requests: keep serving until teardown
            }
            ParsedReq r = parse_request(read_request(cfd));
            std::string resp = handle(r);
            gp::net::send_all(cfd, resp.data(), resp.size());
            ::close(cfd);
        }
    }

    std::string handle(const ParsedReq& r) {
        std::lock_guard lk(mu);
        ++total_requests;
        if (r.method == "GET" && r.path.rfind("/sslvpnd/prelogin.xml", 0) == 0) {
            return http_response(200, "<prelogin><session_id>TESTIKEY</session_id></prelogin>",
                                 {{"Set-Cookie", "IKEY=abc; Path=/; HttpOnly"}});
        }
        if (r.method == "GET" && r.path == "/sslvpn-login") {
            return http_response(200,
                                 "<html><body><form action=\"/sslvpn-login\" method=\"post\">"
                                 "<input type=\"hidden\" name=\"IKEY\" value=\"TESTIKEY\">"
                                 "</form></body></html>");
        }
        if (r.method == "POST" && r.path == "/sslvpn-login") {
            ++login_posts;
            last_login_body = r.body;
            if (!expected_password.empty() &&
                r.body.find("password=" + expected_password) == std::string::npos) {
                return http_response(401, "bad credentials");
            }
            return http_response(200, "ok", {{"Set-Cookie", "GPSESSION=sess1; Path=/"}});
        }
        if (r.method == "GET" && r.path.rfind("/portal/index.html", 0) == 0) {
            return http_response(200,
                                 "<html><body><form action=\"/tunnel/start\" method=\"post\">"
                                 "<input type=\"hidden\" name=\"token\" value=\"t1\">"
                                 "</form></body></html>");
        }
        if (r.method == "POST" && r.path == "/tunnel/start") {
            ++tunnel_posts;
            if (tunnel_posts == 1)
                return http_response(302, "",
                                     {{"Location", base_url() + "/tunnel/start?proto=ipsec"}});
            return http_response(200, "renewed");
        }
        return http_response(404, "not found");
    }

    int totals() {
        std::lock_guard lk(mu);
        return total_requests;
    }
};

// Fake tunnel backend for flow tests (no handshake certificate presented).
class FakeTransport : public tunnel::TunnelTransport {
   public:
    bool present_cert = false;
    std::string metadata_xml;
    int connect_calls = 0;
    int disconnect_calls = 0;
    std::string last_cookie_header;

    bool connect(const tunnel::TunnelConfig&, const std::string& cookie_header,
                 CertCallback on_cert, std::string* err) override {
        ++connect_calls;
        last_cookie_header = cookie_header;
        if (present_cert && !on_cert({})) {
            if (err)
                *err = "certificate rejected";
            return false;
        }
        connected_ = true;
        return true;
    }
    void disconnect() override {
        ++disconnect_calls;
        connected_ = false;
    }
    bool connected() const override { return connected_; }
    std::string session_metadata_xml() const override { return metadata_xml; }

   private:
    bool connected_ = false;
};

std::string unique_cookie_dir() {
    char tmpl[] = "/tmp/gp_flow_XXXXXX";
    int fd = mkstemp(tmpl);
    REQUIRE(fd >= 0);
    ::close(fd);
    ::unlink(tmpl);  // leave a free, unique name for the directory
    return tmpl;
}

ClientConfig make_cfg(const GatewayFixture& gw, const std::string& cookie_dir) {
    ClientConfig cfg;
    cfg.gateway.gateway_host = "127.0.0.1";
    cfg.gateway.base_url = gw.base_url();
    cfg.cookie_dir = cookie_dir;
    cfg.tunnel_cfg.proto = "ipsec";
    cfg.session_extend_interval_s = 1;
    return cfg;
}

bool parse_args(const std::vector<std::string>& args, ClientConfig& out,
                std::string* err = nullptr) {
    std::vector<char*> ptrs;
    for (const auto& a : args)
        ptrs.push_back(const_cast<char*>(a.c_str()));
    return parse_gpclient_args(static_cast<int>(ptrs.size()), ptrs.data(), out, err);
}

// Installs a collecting trace sink; clears it on destruction (RAII, so a
// failing REQUIRE cannot leak the sink into later tests).
struct TraceCapture {
    std::mutex mu;
    std::vector<std::string> lines;

    TraceCapture() {
        gp::trace::set_sink([this](const std::string& l) {
            std::lock_guard lk(mu);
            lines.push_back(l);
        });
    }
    ~TraceCapture() { gp::trace::set_sink(nullptr); }
    TraceCapture(const TraceCapture&) = delete;
    TraceCapture& operator=(const TraceCapture&) = delete;

    bool any_contains(const std::string& needle) {
        std::lock_guard lk(mu);
        for (const auto& l : lines)
            if (l.find(needle) != std::string::npos)
                return true;
        return false;
    }
    size_t count() {
        std::lock_guard lk(mu);
        return lines.size();
    }
};

}  // namespace

// ---------------------------------------------------------------------------
// Credential readers (H-3: secrets from streams/files, never argv)
// ---------------------------------------------------------------------------

TEST(clientflow, read_credentials_valid) {
    std::istringstream iss("alice\nsecret123\n");
    Credentials c;
    std::string err;
    CHECK(read_credentials(iss, &c, &err));
    CHECK_EQ(c.username, std::string("alice"));
    CHECK_EQ(c.password, std::string("secret123"));
}

TEST(clientflow, read_credentials_missing_password_line) {
    std::istringstream iss("alice\n");
    Credentials c;
    std::string err;
    CHECK(!read_credentials(iss, &c, &err));
    CHECK(err.find("password") != std::string::npos);
}

TEST(clientflow, read_credentials_empty_username) {
    std::istringstream iss("\nsecret\n");
    Credentials c;
    std::string err;
    CHECK(!read_credentials(iss, &c, &err));
    CHECK(err.find("username") != std::string::npos);
}

TEST(clientflow, read_credentials_rejects_control_chars) {
    std::istringstream iss("al\x01ice\nsecret\n");
    Credentials c;
    std::string err;
    CHECK(!read_credentials(iss, &c, &err));
    CHECK(err.find("control") != std::string::npos);
}

// ---------------------------------------------------------------------------
// gpclient CLI parsing
// ---------------------------------------------------------------------------

TEST(clientflow, args_valid_direct) {
    ClientConfig cfg;
    std::string err;
    CHECK(parse_args(
        {"gpclient", "--gateway", "gw.example.com", "--user", "alice", "--password-on-stdin"}, cfg,
        &err));
    CHECK_EQ(cfg.gateway.gateway_host, std::string("gw.example.com"));
    CHECK_EQ(cfg.gateway.base_url, std::string("https://gw.example.com"));
    CHECK_EQ(cfg.username, std::string("alice"));
    CHECK(cfg.password_on_stdin);
    CHECK(!cfg.browser_auth);
}

TEST(clientflow, args_valid_browser) {
    ClientConfig cfg;
    CHECK(parse_args({"gpclient", "--gateway", "h.example.com", "--browser-auth"}, cfg));
    CHECK(cfg.browser_auth);
}

TEST(clientflow, args_missing_gateway) {
    ClientConfig cfg;
    std::string err;
    CHECK(!parse_args({"gpclient", "--user", "a", "--password-on-stdin"}, cfg, &err));
    CHECK(err.find("--gateway") != std::string::npos);
}

TEST(clientflow, args_mutually_exclusive_password_sources) {
    ClientConfig cfg;
    std::string err;
    CHECK(!parse_args({"gpclient", "--gateway", "h", "--user", "a", "--password-on-stdin",
                       "--credentials-file", "/tmp/x"},
                      cfg, &err));
    CHECK(err.find("mutually exclusive") != std::string::npos);
}

TEST(clientflow, args_direct_requires_password_source) {
    ClientConfig cfg;
    std::string err;
    CHECK(!parse_args({"gpclient", "--gateway", "h", "--user", "a"}, cfg, &err));
    CHECK(err.find("password") != std::string::npos);
}

TEST(clientflow, args_stdin_requires_user) {
    ClientConfig cfg;
    std::string err;
    CHECK(!parse_args({"gpclient", "--gateway", "h", "--password-on-stdin"}, cfg, &err));
    CHECK(err.find("--user") != std::string::npos);
}

TEST(clientflow, args_credentials_file_needs_no_user) {
    ClientConfig cfg;
    CHECK(parse_args({"gpclient", "--gateway", "h", "--credentials-file", "/tmp/creds"}, cfg));
    CHECK_EQ(cfg.credentials_file, std::string("/tmp/creds"));
}

TEST(clientflow, args_security_switches_passthrough) {
    ClientConfig cfg;
    CHECK(parse_args(
        {"gpclient", "--gateway", "h", "--browser-auth", "--pin-cert", "aa:bb", "--check-crl"},
        cfg));
    REQUIRE(cfg.security.pinned_gateway_cert_sha256.has_value());
    CHECK_EQ(*cfg.security.pinned_gateway_cert_sha256, std::string("aa:bb"));
    CHECK(cfg.security.check_crl);
}

TEST(clientflow, args_invalid_interval) {
    ClientConfig cfg;
    std::string err;
    CHECK(!parse_args({"gpclient", "--gateway", "h", "--browser-auth", "--extend-interval-s", "0"},
                      cfg, &err));
    CHECK(!err.empty());
}

// ---------------------------------------------------------------------------
// Direct-credentials flow (end to end against the fixture gateway)
// ---------------------------------------------------------------------------

TEST(clientflow, direct_flow_end_to_end) {
    GatewayFixture gw;
    REQUIRE(gw.start());
    auto dir = unique_cookie_dir();
    ClientConfig cfg = make_cfg(gw, dir);

    auto h = std::make_shared<std::unique_ptr<FakeTransport>>(std::make_unique<FakeTransport>());
    FakeTransport* raw = h->get();
    raw->metadata_xml =
        "<tunnel-info><user user-expires=\"2030-01-01T00:00:00Z\">alice</user></tunnel-info>";
    ClientFlow::TransportFactory factory =
        [h]() mutable -> std::unique_ptr<tunnel::TunnelTransport> {
        return std::unique_ptr<tunnel::TunnelTransport>(std::move(*h));
    };

    auto flow = ClientFlow::create(cfg, nullptr);
    REQUIRE(flow != nullptr);
    std::string err;
    bool ok_direct = flow->run_direct({"alice", "secret123"}, factory, &err);
    if (!ok_direct)
        std::cerr << "run_direct failed: " << err << "\n";
    CHECK(ok_direct);

    // Portal exchange happened with the right credentials.
    {
        std::lock_guard lk(gw.mu);
        CHECK_EQ(gw.login_posts, 1);
        CHECK(gw.last_login_body.find("username=alice") != std::string::npos);
        CHECK(gw.last_login_body.find("password=secret123") != std::string::npos);
    }

    // Tunnel endpoint obtained from the connect redirect; cookies forwarded.
    CHECK_EQ(flow->tunnel_endpoint(), gw.base_url() + "/tunnel/start?proto=ipsec");
    CHECK(raw->connect_calls == 1);
    CHECK(raw->last_cookie_header.find("IKEY=abc") != std::string::npos);
    CHECK(raw->last_cookie_header.find("GPSESSION=sess1") != std::string::npos);

    // Session metadata surfaced through the tunnel client.
    REQUIRE(flow->metadata() != nullptr);
    CHECK(flow->metadata()->present);
    CHECK_EQ(flow->metadata()->user, std::string("alice"));

    // Session-extension loop renews on its 1s interval.
    std::this_thread::sleep_for(std::chrono::milliseconds(2300));
    CHECK(flow->session_extensions() >= 2);

    flow->stop();  // joins the extension thread, disconnects the tunnel
    CHECK(raw->disconnect_calls == 1);
}

TEST(clientflow, direct_flow_rejects_wrong_password_without_leaking_it) {
    GatewayFixture gw;
    REQUIRE(gw.start());
    gw.expected_password = "right-pass";
    auto dir = unique_cookie_dir();
    ClientConfig cfg = make_cfg(gw, dir);

    auto flow = ClientFlow::create(cfg, nullptr);
    REQUIRE(flow != nullptr);
    std::string err;
    CHECK(!flow->run_direct(
        {"alice", "wrong-pass"}, [] { return std::unique_ptr<tunnel::TunnelTransport>(nullptr); },
        &err));
    CHECK(err.find("401") != std::string::npos);
    // The error must not contain the password (H-3/M-3).
    CHECK(err.find("wrong-pass") == std::string::npos);
}

TEST(clientflow, posture_failure_aborts_before_any_gateway_traffic) {
    GatewayFixture gw;
    REQUIRE(gw.start());
    auto dir = unique_cookie_dir();
    ClientConfig cfg = make_cfg(gw, dir);
    cfg.posture_check.program = "/bin/false";  // always exits 1

    auto flow = ClientFlow::create(cfg, nullptr);
    REQUIRE(flow != nullptr);
    std::string err;
    CHECK(!flow->run_direct(
        {"alice", "x"}, [] { return std::unique_ptr<tunnel::TunnelTransport>(nullptr); }, &err));
    CHECK(err.find("posture") != std::string::npos);
    CHECK_EQ(gw.totals(), 0);  // fail closed: nothing reached the gateway
}

TEST(clientflow, missing_tunnel_backend_reports_clearly) {
    GatewayFixture gw;
    REQUIRE(gw.start());
    auto dir = unique_cookie_dir();
    ClientConfig cfg = make_cfg(gw, dir);  // want_tunnel stays true

    auto flow = ClientFlow::create(cfg, nullptr);
    REQUIRE(flow != nullptr);
    std::string err;
    CHECK(!flow->run_direct(
        {"alice", "x"}, [] { return std::unique_ptr<tunnel::TunnelTransport>(nullptr); }, &err));
    CHECK(err.find("--no-tunnel") != std::string::npos);
}

TEST(clientflow, no_tunnel_mode_stops_at_endpoint) {
    GatewayFixture gw;
    REQUIRE(gw.start());
    auto dir = unique_cookie_dir();
    ClientConfig cfg = make_cfg(gw, dir);
    cfg.want_tunnel = false;

    auto flow = ClientFlow::create(cfg, nullptr);
    REQUIRE(flow != nullptr);
    std::string err;
    CHECK(flow->run_direct(
        {"alice", "x"}, [] { return std::unique_ptr<tunnel::TunnelTransport>(nullptr); }, &err));
    CHECK_EQ(flow->tunnel_endpoint(), gw.base_url() + "/tunnel/start?proto=ipsec");
    CHECK(flow->metadata() == nullptr);  // no tunnel client was created
    flow->stop();
}

// ---------------------------------------------------------------------------
// Browser/IdP auth flow (one-shot callback listener, H-1)
// ---------------------------------------------------------------------------

namespace {

// Simulated GP browser plugin: POSTs the payload to the callback URL.
bool post_to_callback(const std::string& callback_url, const std::string& payload) {
    std::string host = "127.0.0.1";
    uint16_t port = 0;
    std::string path;
    // http://127.0.0.1:PORT/<token>
    auto scheme_end = callback_url.find("://");
    size_t rest = scheme_end + 3;
    auto colon = callback_url.rfind(':');
    auto slash = callback_url.find('/', rest);
    if (colon != std::string::npos && (slash == std::string::npos || colon < slash)) {
        host = callback_url.substr(rest, colon - rest);
        port = static_cast<uint16_t>(std::atoi(callback_url.c_str() + colon + 1));
    }
    path = (slash == std::string::npos) ? "/" : callback_url.substr(slash);

    int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
        return false;
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    bool ok = ::connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == 0;
    if (ok) {
        std::string req = "POST " + path +
                          " HTTP/1.1\r\nHost: 127.0.0.1\r\n"
                          "Content-Type: application/octet-stream\r\n"
                          "Content-Length: " +
                          std::to_string(payload.size()) +
                          "\r\n"
                          "Connection: close\r\n\r\n" +
                          payload;
        gp::net::send_all(fd, req.data(), req.size());
    }
    // Drain the response (best effort).
    char tmp[4096];
    while (::recv(fd, tmp, sizeof(tmp), 0) > 0) {
    }
    ::close(fd);
    return ok;
}

}  // namespace

TEST(clientflow, browser_auth_flow_end_to_end) {
    GatewayFixture gw;
    REQUIRE(gw.start());
    auto dir = unique_cookie_dir();
    ClientConfig cfg = make_cfg(gw, dir);
    cfg.browser_auth = true;
    cfg.security.callback_timeout = std::chrono::seconds(3);

    auto h = std::make_shared<std::unique_ptr<FakeTransport>>(std::make_unique<FakeTransport>());
    FakeTransport* raw = h->get();
    ClientFlow::TransportFactory factory =
        [h]() mutable -> std::unique_ptr<tunnel::TunnelTransport> {
        return std::unique_ptr<tunnel::TunnelTransport>(std::move(*h));
    };

    auto flow = ClientFlow::create(cfg, nullptr);
    REQUIRE(flow != nullptr);

    std::mutex mu;
    std::condition_variable cv;
    std::string callback_url;
    bool ready = false;
    bool run_ok = false;
    std::string run_err;
    std::thread runner([&] {
        run_ok = flow->run_browser_auth(
            factory,
            [&](const std::string&, const std::string& cb_url) {
                std::lock_guard lk(mu);
                callback_url = cb_url;
                ready = true;
                cv.notify_all();
            },
            &run_err);
    });

    {
        std::unique_lock lk(mu);
        CHECK(cv.wait_for(lk, std::chrono::seconds(5), [&] { return ready; }));
    }
    REQUIRE(!callback_url.empty());
    CHECK(callback_url.rfind("http://127.0.0.1:", 0) == 0);

    // The GP plugin posts "globalprotectcallback:<payload>".
    CHECK(post_to_callback(callback_url, "globalprotectcallback:SAML-PAYLOAD-42"));

    runner.join();
    if (!run_ok)
        std::cerr << "run_browser_auth failed: " << run_err << "\n";
    CHECK(run_ok);

    // The payload reached the gateway exactly once, in the configured field.
    {
        std::lock_guard lk(gw.mu);
        CHECK_EQ(gw.login_posts, 1);
        CHECK(gw.last_login_body.find("SAMLResponse=") != std::string::npos);
        CHECK(gw.last_login_body.find("SAML-PAYLOAD-42") != std::string::npos);
    }
    CHECK_EQ(flow->tunnel_endpoint(), gw.base_url() + "/tunnel/start?proto=ipsec");
    CHECK(raw->connect_calls == 1);
    flow->stop();
}

TEST(clientflow, browser_auth_rejects_payload_without_marker) {
    GatewayFixture gw;
    REQUIRE(gw.start());
    auto dir = unique_cookie_dir();
    ClientConfig cfg = make_cfg(gw, dir);
    cfg.browser_auth = true;

    auto flow = ClientFlow::create(cfg, nullptr);
    REQUIRE(flow != nullptr);

    std::mutex mu;
    std::condition_variable cv;
    std::string callback_url;
    bool ready = false;
    std::thread runner([&] {
        flow->run_browser_auth(nullptr, [&](const std::string&, const std::string& cb_url) {
            std::lock_guard lk(mu);
            callback_url = cb_url;
            ready = true;
            cv.notify_all();
        });
    });

    {
        std::unique_lock lk(mu);
        CHECK(cv.wait_for(lk, std::chrono::seconds(5), [&] { return ready; }));
    }
    REQUIRE(!callback_url.empty());
    CHECK(post_to_callback(callback_url, "attacker-injected-junk"));

    runner.join();
    // No login traffic happened at all: the payload never reached the gateway.
    {
        std::lock_guard lk(gw.mu);
        CHECK_EQ(gw.login_posts, 0);
    }
}

// ---------------------------------------------------------------------------
// Debug tracing (gp::trace): coverage of the process and M-3 redaction
// ---------------------------------------------------------------------------

TEST(clientflow, trace_off_by_default_and_format_joins) {
    CHECK(!gp::trace::enabled());
    gp::trace::emit("nothing goes anywhere");  // no sink: must be a safe no-op
    CHECK_EQ(gp::trace::format(std::string("one")), std::string("one"));
    CHECK_EQ(gp::trace::format("http: GET ", "/x", " -> HTTP ", 200),
             std::string("http: GET /x -> HTTP 200"));
}

TEST(clientflow, trace_covers_full_process) {
    GatewayFixture gw;
    REQUIRE(gw.start());
    auto dir = unique_cookie_dir();
    ClientConfig cfg = make_cfg(gw, dir);
    TraceCapture tr;

    auto h = std::make_shared<std::unique_ptr<FakeTransport>>(std::make_unique<FakeTransport>());
    FakeTransport* raw = h->get();
    raw->metadata_xml =
        "<tunnel-info><user user-expires=\"2030-01-01T00:00:00Z\">alice</user></tunnel-info>";
    ClientFlow::TransportFactory factory =
        [h]() mutable -> std::unique_ptr<tunnel::TunnelTransport> {
        return std::unique_ptr<tunnel::TunnelTransport>(std::move(*h));
    };

    auto flow = ClientFlow::create(cfg, nullptr);
    REQUIRE(flow != nullptr);
    std::string err;
    CHECK(flow->run_direct({"alice", "secret123"}, factory, &err));
    flow->stop();

    // Every stage of the process is visible in order.
    const char* needles[] = {
        "flow: direct auth for user 'alice'",
        "flow: prelogin",
        "http: GET /sslvpnd/prelogin.xml -> HTTP 200",
        "prelogin: session established",
        "cookies: stored 'IKEY'",
        "flow: login",
        "login: form discovered (1 hidden fields)",
        "login: submitting credentials to /sslvpn-login",
        "http: POST /sslvpn-login (3 fields) -> HTTP 200",
        "login: accepted (HTTP 200)",
        "flow: connect",
        "connect: portal form discovered (1 hidden fields)",
        "connect: posting portal form to /tunnel/start",
        "connect: tunnel endpoint = ",
        "flow: tunnel connect: ",
        "tunnel: connecting to ",
        "tunnel: session user 'alice'",
        "flow: session extension loop started (every 1s)",
        "flow: stopped after",
    };
    for (const char* n : needles)
        CHECK(tr.any_contains(n));
}

TEST(clientflow, trace_never_contains_credentials_or_cookies) {
    GatewayFixture gw;
    REQUIRE(gw.start());
    auto dir = unique_cookie_dir();
    ClientConfig cfg = make_cfg(gw, dir);
    TraceCapture tr;

    auto h = std::make_shared<std::unique_ptr<FakeTransport>>(std::make_unique<FakeTransport>());
    FakeTransport* raw = h->get();
    ClientFlow::TransportFactory factory =
        [h]() mutable -> std::unique_ptr<tunnel::TunnelTransport> {
        return std::unique_ptr<tunnel::TunnelTransport>(std::move(*h));
    };

    auto flow = ClientFlow::create(cfg, nullptr);
    REQUIRE(flow != nullptr);
    std::string err;
    CHECK(flow->run_direct({"traceuser", "Sup3rS3cret-Pw!"}, factory, &err));
    flow->stop();
    CHECK(raw->connect_calls == 1);

    // M-3: no line may carry the password, a form-encoded credential field,
    // the session id (IKEY value), or any cookie VALUE. Names are fine.
    const char* forbidden[] = {"Sup3rS3cret-Pw!", "password=", "TESTIKEY", "sess1"};
    {
        std::vector<std::string> snapshot;
        {
            std::lock_guard lk(tr.mu);
            snapshot = tr.lines;
        }
        REQUIRE(!snapshot.empty());
        for (const auto& line : snapshot) {
            for (const char* f : forbidden)
                CHECK(line.find(f) == std::string::npos);
        }
    }
}

TEST(clientflow, trace_never_contains_callback_payload) {
    GatewayFixture gw;
    REQUIRE(gw.start());
    auto dir = unique_cookie_dir();
    ClientConfig cfg = make_cfg(gw, dir);
    cfg.browser_auth = true;
    cfg.security.callback_timeout = std::chrono::seconds(3);
    TraceCapture tr;

    auto h = std::make_shared<std::unique_ptr<FakeTransport>>(std::make_unique<FakeTransport>());
    ClientFlow::TransportFactory factory =
        [h]() mutable -> std::unique_ptr<tunnel::TunnelTransport> {
        return std::unique_ptr<tunnel::TunnelTransport>(std::move(*h));
    };

    auto flow = ClientFlow::create(cfg, nullptr);
    REQUIRE(flow != nullptr);

    std::mutex mu;
    std::condition_variable cv;
    std::string callback_url;
    bool ready = false;
    std::thread runner([&] {
        flow->run_browser_auth(factory, [&](const std::string&, const std::string& cb_url) {
            std::lock_guard lk(mu);
            callback_url = cb_url;
            ready = true;
            cv.notify_all();
        });
    });

    {
        std::unique_lock lk(mu);
        CHECK(cv.wait_for(lk, std::chrono::seconds(5), [&] { return ready; }));
    }
    REQUIRE(!callback_url.empty());

    CHECK(post_to_callback(callback_url, "globalprotectcallback:SAML-TRACE-PAYLOAD-X9"));
    runner.join();
    flow->stop();

    // The browser-auth stages are traced...
    CHECK(tr.any_contains("flow: browser auth: callback listener on 127.0.0.1:"));
    CHECK(tr.any_contains("flow: browser auth: instructions page on 127.0.0.1:"));
    CHECK(tr.any_contains("callback: delivered ("));
    CHECK(
        tr.any_contains("saml_login: posting callback payload to /sslvpn-login as 'SAMLResponse'"));
    // ...but the payload itself never is (M-3).
    {
        std::vector<std::string> snapshot;
        {
            std::lock_guard lk(tr.mu);
            snapshot = tr.lines;
        }
        for (const auto& line : snapshot)
            CHECK(line.find("SAML-TRACE-PAYLOAD-X9") == std::string::npos);
    }
}

int main() {
    return gp::test::Registry::instance().run_all();
}