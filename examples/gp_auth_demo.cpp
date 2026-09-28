// End-to-end demonstration of the fixed browser-auth flow:
//   1. parse security switches (all lenient modes opt-in, all reported);
//   2. start the token-protected AuthServer (escaped HTML page);
//   3. start the token-protected CallbackListener;
//   4. simulate the browser: GET the one-shot auth URL, then POST the
//      SAML callback payload to the listener;
//   5. print results.
//
// Usage: gp_auth_demo [--ignore-tls-errors] [--allow-remote-callback] ...
#include <chrono>
#include <iostream>

#include "gp/auth_server.h"
#include "gp/callback_listener.h"
#include "gp/http_client.h"
#include "gp/security_options.h"

int main(int argc, char** argv) {
    using namespace gp;

    SecurityOptions opts;
    std::string err;
    if (!SecurityOptions::from_args(argc, argv, opts, &err)) {
        std::cerr << "argument error: " << err << "\n";
        return 2;
    }

    std::cout << "== effective security policy ==\n";
    for (const auto& note : opts.describe_policy())
        std::cout << "  " << note << "\n";

    // --- Auth server (H-2): escaped page, loopback-only by default ----------
    auth::AuthServer server(opts);
    auth::AuthServerConfig cfg;
    cfg.page_title = "GlobalProtect Authentication";
    cfg.portal_display_url = "https://gp.example.com/globalprotect/login.jsp?tag=<demo>";
    if (!server.start(cfg, &err)) {
        std::cerr << "auth server: " << err << "\n";
        return 1;
    }
    std::cout << "== auth page (open in browser) ==\n  " << server.url() << "\n";

    // --- Callback listener (H-1): token-authenticated, capped, timed --------
    auth::CallbackListener listener(opts);
    if (!listener.start(&err)) {
        std::cerr << "callback listener: " << err << "\n";
        return 1;
    }
    std::cout << "== callback endpoint ==\n  port file (0600): " << listener.port_file() << "\n";

    // --- Simulate the browser -------------------------------------------------
    http::HttpClient browser(opts);
    auto page = browser.get(server.url());
    std::cout << "== simulated browser GET auth page: " << (page.ok ? "OK" : "FAILED")
              << " status=" << page.status_code << "\n";

    const std::string payload = "globalprotectcallback:eyJhbGciOiJIUzI1NiJ9.demo-saml-response";
    auto cb_url = "http://127.0.0.1:" + std::to_string(listener.port()) + listener.url_path();
    auto posted = browser.post(cb_url, payload);
    std::cout << "== simulated browser POST callback: " << (posted.ok ? "OK" : "FAILED")
              << " status=" << posted.status_code << "\n";

    auto visit = server.wait_for_visit();
    auto cb = listener.wait_for_callback();
    std::cout << "== result ==\n  auth page: " << visit.reason << "\n"
              << "  callback: " << cb.reason << " (" << cb.payload.size()
              << " bytes received, payload redacted from this log)\n";

    return (visit.status == auth::AuthServerResult::Status::Visited &&
            cb.status == auth::CallbackResult::Status::Delivered)
               ? 0
               : 1;
}
