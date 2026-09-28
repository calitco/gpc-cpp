// One-shot auth page server — the C++ replacement for auth_server.rs
// (finding H-2).
//
// Fixes:
//  - only a locally generated HTML template is served; every portal-provided
//    value passes through html::escape_text (no more XSS from a hostile
//    portal on a 127.0.0.1 origin);
//  - redirect targets are validated at start() (scheme, control chars,
//    optional host allowlist) — a malformed portal URL fails startup cleanly
//    instead of panicking and hanging auth forever;
//  - request cap + lifetime deadline (no infinite serve loop);
//  - non-loopback bind is refused unless --allow-remote-callback was given.
#pragma once

#include <cstdint>
#include <memory>
#include <optional>
#include <string>

#include "gp/security_options.h"

namespace gp::auth {

struct AuthServerConfig {
    std::string bind_address = "127.0.0.1";
    uint16_t port = 0;  // 0 = ephemeral
    // Raw (untrusted) display values — escaped by the server before rendering.
    std::string page_title = "GlobalProtect Authentication";
    std::string portal_display_url;
    // If set, serve a 302 to this URL instead of HTML. Validated at start().
    std::optional<std::string> redirect_url;
};

struct AuthServerResult {
    enum class Status { Visited, Timeout, RequestLimit, Error };
    Status status = Status::Error;
    std::string reason;
};

class AuthServer {
   public:
    explicit AuthServer(const SecurityOptions& opts);
    ~AuthServer();

    bool start(const AuthServerConfig& cfg, std::string* err = nullptr);

    uint16_t port() const;
    const std::string& token() const;
    // Full one-shot URL: http://<bind>:<port>/<token>
    std::string url() const;

    // Block until the one-shot URL is visited, the deadline elapses, or the
    // request cap is hit.
    AuthServerResult wait_for_visit();

    void stop();

   private:
    void worker_loop();
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace gp::auth
