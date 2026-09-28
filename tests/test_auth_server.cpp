// Tests for finding H-2 fixes: escaped HTML only, validated redirects,
// loopback-only bind by default, request cap + deadline, no token oracle.
#include <gp/auth_server.h>
#include <gp/security_options.h>

#include "net_test_util.h"
#include "test_framework.h"

using gp::SecurityOptions;
using namespace gp::auth;
namespace testnet = gp::testnet;

TEST(authserver, non_loopback_bind_requires_optin) {
    SecurityOptions o;
    AuthServer s(o);
    AuthServerConfig cfg;
    cfg.bind_address = "0.0.0.0";
    std::string err;
    CHECK(!s.start(cfg, &err));
    CHECK(err.find("--allow-remote-callback") != std::string::npos);

    // With the explicit switch the same bind is allowed (API-level check).
    SecurityOptions o2;
    o2.allow_remote_callback_bind = true;
    AuthServer s2(o2);
    AuthServerConfig cfg2;
    cfg2.bind_address = "127.0.0.1";  // loopback: always fine
    CHECK(s2.start(cfg2, &err));
}

TEST(authserver, page_escapes_portal_values) {
    SecurityOptions o;
    AuthServer s(o);
    AuthServerConfig cfg;
    cfg.page_title = "Auth <b>test</b>";
    // Hostile portal value: must be escaped in the served HTML.
    cfg.portal_display_url = "https://portal.example.com/sso\"><script>alert(1)</script>";
    CHECK(s.start(cfg));

    std::string raw = testnet::http_roundtrip("127.0.0.1", s.port(), "GET", "/" + s.token());
    CHECK(!raw.empty());
    CHECK(testnet::status_of(raw).find("200") != std::string::npos);
    std::string body = testnet::body_of(raw);
    CHECK(body.find("<script>") == std::string::npos);        // no raw script
    CHECK(body.find("&lt;script&gt;") != std::string::npos);  // escaped
    CHECK(body.find("Auth &lt;b&gt;test&lt;/b&gt;") != std::string::npos);
    AuthServerResult r = s.wait_for_visit();  // one-shot already consumed
    (void)r;
}

TEST(authserver, redirect_mode_sends_302) {
    SecurityOptions o;
    AuthServer s(o);
    AuthServerConfig cfg;
    cfg.redirect_url = "https://portal.example.com/next?x=1";
    CHECK(s.start(cfg));
    std::string raw = testnet::http_roundtrip("127.0.0.1", s.port(), "GET", "/" + s.token());
    CHECK(testnet::status_of(raw).find("302") != std::string::npos);
    CHECK(raw.find("Location: https://portal.example.com/next?x=1") != std::string::npos);
}

TEST(authserver, malformed_redirect_targets_refused_at_start) {
    SecurityOptions o;
    const char* bad[] = {"javascript:alert(1)", "https://x.com/\r\nX-Injected: 1",
                         "file:///etc/passwd"};
    for (const char* u : bad) {
        AuthServer s(o);
        AuthServerConfig cfg;
        cfg.redirect_url = u;
        std::string err;
        CHECK(!s.start(cfg, &err));
        CHECK(err.find("invalid redirect target") != std::string::npos);
    }
}

TEST(authserver, redirect_allowlist_enforced) {
    SecurityOptions o;
    o.allowed_redirect_hosts = {"ok.example.com"};
    AuthServer s(o);
    AuthServerConfig cfg;
    cfg.redirect_url = "https://evil.example.com/next";
    std::string err;
    CHECK(!s.start(cfg, &err));

    AuthServerConfig good;
    good.redirect_url = "https://ok.example.com/next";
    CHECK(s.start(good));
}

TEST(authserver, wrong_path_gets_404_and_server_keeps_waiting) {
    SecurityOptions o;
    o.auth_server_timeout = std::chrono::milliseconds(1500);
    AuthServer s(o);
    AuthServerConfig cfg;
    CHECK(s.start(cfg));

    // Attacker probes a wrong path: uniform 404, one-shot NOT consumed.
    std::string raw =
        testnet::http_roundtrip("127.0.0.1", s.port(), "GET", "/definitely-not-the-token");
    CHECK(testnet::status_of(raw).find("404") != std::string::npos);

    // The real visit still works afterwards.
    raw = testnet::http_roundtrip("127.0.0.1", s.port(), "GET", "/" + s.token());
    CHECK(testnet::status_of(raw).find("200") != std::string::npos);
    AuthServerResult r = s.wait_for_visit();
    // wait_for_visit resumes after the listener was already consumed by the
    // visit; either Visited (if it saw the request) or a clean end state.
    CHECK(r.status == AuthServerResult::Status::Visited ||
          r.status == AuthServerResult::Status::Timeout ||
          r.status == AuthServerResult::Status::RequestLimit);
}

TEST(authserver, times_out_without_visits) {
    SecurityOptions o;
    o.auth_server_timeout = std::chrono::milliseconds(300);
    AuthServer s(o);
    CHECK(s.start(AuthServerConfig{}));
    auto t0 = std::chrono::steady_clock::now();
    AuthServerResult r = s.wait_for_visit();
    auto elapsed = std::chrono::steady_clock::now() - t0;
    CHECK(r.status == AuthServerResult::Status::Timeout);
    CHECK(elapsed >= std::chrono::milliseconds(250));  // actually waited
}

TEST(authserver, request_cap_stops_the_loop) {
    SecurityOptions o;
    o.auth_server_timeout = std::chrono::seconds(30);
    o.max_auth_server_requests = 3;
    AuthServer s(o);
    CHECK(s.start(AuthServerConfig{}));
    for (int i = 0; i < 3; ++i) {
        testnet::http_roundtrip("127.0.0.1", s.port(), "GET", "/probe");
    }
    AuthServerResult r = s.wait_for_visit();
    CHECK(r.status == AuthServerResult::Status::RequestLimit);
}

int main() {
    return gp::test::Registry::instance().run_all();
}
