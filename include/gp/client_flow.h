// End-to-end client orchestration (Wave H) — the gpclient flow as a library:
//
//   posture check -> prelogin -> login (direct credentials OR browser/IdP
//   auth via AuthServer + CallbackListener) -> portal connect -> tunnel
//   (gp::tunnel::TunnelClient with an injected transport) -> session
//   extension loop.
//
// Security properties:
//  - Credentials come from stdin or a 0600 file, NEVER argv (H-3); the
//    password is read once and never copied into error strings.
//  - The browser-auth branch uses the one-shot token callback listener (H-1)
//    and the local auth page server (H-2); the GUI host receives its URL on
//    stdin, never argv (gui.h).
//  - Posture failure is fail-closed: the flow stops BEFORE any credential or
//    session traffic.
//  - The IdP callback payload must carry the "globalprotectcallback:" marker;
//    anything else is rejected. The payload is POSTed exactly once and never
//    appears in error strings.
//  - The tunnel step goes through gp::tunnel (Wave G): strict endpoint
//    validation + certificate policy on every presented certificate. If no
//    transport backend is available in this build, the client reports that
//    explicitly instead of weakening anything.
//  - No static state: ClientFlow owns everything; concurrent flows are safe.
#pragma once

#include <atomic>
#include <condition_variable>
#include <functional>
#include <istream>
#include <memory>
#include <mutex>
#include <string>
#include <thread>

#include "gp/auth_server.h"
#include "gp/callback_listener.h"
#include "gp/gateway_client.h"
#include "gp/posture.h"
#include "gp/security_options.h"
#include "gp/tunnel_client.h"

namespace gp::client {

struct Credentials {
    std::string username;
    std::string password;
};

// Read "username\npassword\n" (trailing newline optional) from `in` — stdin
// or an already-opened 0600 file. Both lines are required and must not be
// empty. Never reads secrets from argv (H-3).
bool read_credentials(std::istream& in, Credentials* out, std::string* err = nullptr);

struct ClientConfig {
    SecurityOptions security;
    gateway::GatewayConfig gateway;
    tunnel::TunnelConfig tunnel_cfg;
    std::string cookie_dir = "/tmp/gpclient-cookies";  // created 0700 by GatewayClient

    // Direct-credentials inputs (browser_auth mode ignores them).
    std::string username;            // --user
    bool password_on_stdin = false;  // --password-on-stdin
    std::string credentials_file;    // --credentials-file (must be 0600)

    // Browser/IdP auth.
    bool browser_auth = false;  // --browser-auth
    std::string gui_program;    // --gui-program (optional GUI host)
    // Where the captured callback payload is POSTed (gateway-dependent).
    std::string callback_return_path = "/sslvpn-login";  // --callback-return-path
    std::string callback_field_name = "SAMLResponse";    // --callback-field

    posture::CheckConfig posture_check;  // empty program == disabled

    int session_extend_interval_s = 300;  // --extend-interval-s (min 1)
    bool want_tunnel = true;              // false: stop after obtaining the endpoint (--no-tunnel)
};

// Resolve direct-credentials inputs from ClientConfig:
//  - --password-on-stdin : username from --user, password = one line on stdin;
//  - --credentials-file  : the 0600 file holds "username\npassword\n".
// Never reads secrets from argv (H-3).
bool read_direct_credentials(const ClientConfig& cfg, Credentials* out, std::string* err = nullptr);

class ClientFlow {
   public:
    using TransportFactory = std::function<std::unique_ptr<tunnel::TunnelTransport>()>;
    // Called once after the callback listener + auth page server are up and
    // BEFORE blocking on the callback. `callback_url` is what the browser must
    // visit/POST to (http://127.0.0.1:<port>/<token>); `auth_page_url` is the
    // local page telling the user where to authenticate.
    using ServersReadyHook =
        std::function<void(const std::string& auth_page_url, const std::string& callback_url)>;

    // Fails if cookie_dir cannot be opened with enforced permissions.
    static std::unique_ptr<ClientFlow> create(const ClientConfig& cfg, std::string* err = nullptr);
    ~ClientFlow();  // stops the extension loop, tunnel, and auth servers

    // Direct credentials: posture -> prelogin -> login -> connect -> tunnel.
    bool run_direct(const Credentials& creds, TransportFactory transport,
                    std::string* err = nullptr);

    // Browser/IdP auth: posture -> prelogin -> start CallbackListener +
    // AuthServer (and the optional GUI host) -> on_ready() -> wait for the
    // one-shot callback -> saml_login(payload) -> connect -> tunnel.
    bool run_browser_auth(TransportFactory transport, const ServersReadyHook& on_ready = nullptr,
                          std::string* err = nullptr);

    // Stop the session-extension loop and tear everything down. Idempotent.
    void stop();

    const tunnel::SessionMetadata* metadata() const;  // valid after a successful run
    const std::string& tunnel_endpoint() const;       // valid after connect()
    int session_extensions() const;                   // successful renewals so far

   private:
    struct Impl;
    explicit ClientFlow(std::unique_ptr<Impl> impl);
    ClientFlow(const ClientFlow&) = delete;
    ClientFlow& operator=(const ClientFlow&) = delete;

    bool run_posture(std::string* err);
    bool finish_connect_and_tunnel(TransportFactory transport, std::string* err);
    void extension_loop();

    std::unique_ptr<Impl> impl_;
};

// CLI parsing for apps/gpclient. Also consumes the shared SecurityOptions
// switches (--ignore-tls-errors, --pin-cert, ...). Returns false on malformed
// or contradictory values; unknown arguments are ignored (as in from_args).
bool parse_gpclient_args(int argc, char** argv, ClientConfig& out, std::string* err = nullptr);

}  // namespace gp::client