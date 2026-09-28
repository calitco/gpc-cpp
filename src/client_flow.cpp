// End-to-end client orchestration — see include/gp/client_flow.h for the flow
// and security properties.
#include "gp/client_flow.h"

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cctype>
#include <chrono>
#include <cstdlib>
#include <iostream>
#include <sstream>

#include "gp/gui.h"
#include "gp/secret_transport.h"
#include "gp/trace.h"

namespace gp::client {

namespace {

std::string trim(const std::string& s) {
    size_t b = s.find_first_not_of(" \t\r\n");
    if (b == std::string::npos)
        return "";
    size_t e = s.find_last_not_of(" \t\r\n");
    return s.substr(b, e - b + 1);
}

// "scheme://host[:port][/path]" -> host without port. "" when malformed.
std::string url_host(const std::string& url) {
    auto scheme_end = url.find("://");
    if (scheme_end == std::string::npos)
        return "";
    size_t start = scheme_end + 3;
    size_t end = url.find_first_of("/?#", start);
    std::string host =
        (end == std::string::npos) ? url.substr(start) : url.substr(start, end - start);
    auto port_at = host.rfind(':');
    if (port_at != std::string::npos && host.find(':', port_at + 1) == std::string::npos)
        host.resize(port_at);
    return host;
}

std::string url_path_of(const std::string& url) {
    auto scheme_end = url.find("://");
    size_t start = (scheme_end == std::string::npos) ? 0 : scheme_end + 3;
    auto slash = url.find('/', start);
    return (slash == std::string::npos) ? "/" : url.substr(slash);
}

// Build the Cookie header for a tunnel endpoint from the gateway cookie jar.
std::string cookie_header_for(const cookies::Store& store, const std::string& endpoint_url) {
    std::string host = url_host(endpoint_url);
    bool https = endpoint_url.rfind("https://", 0) == 0;
    auto cs = store.for_request(host, https, url_path_of(endpoint_url));
    std::string header;
    for (size_t i = 0; i < cs.size(); ++i) {
        if (i)
            header += "; ";
        header += cs[i].name + "=" + cs[i].value;
    }
    return header;
}

}  // namespace

bool read_credentials(std::istream& in, Credentials* out, std::string* err) {
    auto fail = [&](const std::string& msg) {
        if (err)
            *err = msg;
        return false;
    };
    std::string user_line, pass_line;
    if (!std::getline(in, user_line))
        return fail("credentials: missing username line");
    if (!std::getline(in, pass_line))
        return fail("credentials: missing password line");
    out->username = trim(user_line);
    out->password = trim(pass_line);
    if (out->username.empty())
        return fail("credentials: empty username");
    if (out->password.empty())
        return fail("credentials: empty password");
    for (unsigned char c : out->username)
        if (c < 0x20 || c == 0x7f)
            return fail("credentials: username contains control characters");
    for (unsigned char c : out->password)
        if (c < 0x09 || (c > 0x0d && c < 0x20) || c == 0x7f)
            return fail("credentials: password contains invalid control characters");
    return true;
}

// Read a credentials file that must be owner-only (0600) unless the operator
// explicitly relaxed key-file permission checks.
bool read_credentials_file(const std::string& path, bool allow_insecure_permissions,
                           Credentials* out, std::string* err) {
    int fd = ::open(path.c_str(), O_RDONLY);
    if (fd < 0) {
        if (err)
            *err = "credentials file: cannot open " + path;
        return false;
    }
    struct stat st;
    bool ok = true;
    if (::fstat(fd, &st) != 0) {
        ok = false;
    } else if ((st.st_mode & S_IWGRP) || (st.st_mode & S_IROTH) || (st.st_mode & S_IWOTH)) {
        if (!allow_insecure_permissions) {
            ok = false;
            if (err)
                *err = "credentials file: group/other permissions set on " + path +
                       " (fix with chmod 600, or use --allow-insecure-key-file)";
        }
    }
    std::string content;
    if (ok) {
        char tmp[4096];
        for (;;) {
            ssize_t n = ::read(fd, tmp, sizeof tmp);
            if (n < 0) {
                ok = false;
                break;
            }
            if (n == 0)
                break;
            content.append(tmp, static_cast<size_t>(n));
        }
    }
    ::close(fd);
    if (!ok) {
        if (err && err->empty())
            *err = "credentials file: read error on " + path;
        return false;
    }
    std::istringstream iss(content);
    return read_credentials(iss, out, err);
}

bool read_direct_credentials(const ClientConfig& cfg, Credentials* out, std::string* err) {
    if (cfg.password_on_stdin) {
        // Protocol: exactly one line on stdin = the password. The username comes
        // from --user. Stdin is never echoed and never appears in argv (H-3).
        out->username = cfg.username;
        std::string pass_line;
        if (!std::getline(std::cin, pass_line)) {
            if (err)
                *err = "password: missing line on stdin";
            return false;
        }
        out->password = trim(pass_line);
        if (out->username.empty()) {
            if (err)
                *err = "password: --user is required with --password-on-stdin";
            return false;
        }
        if (out->password.empty()) {
            if (err)
                *err = "password: empty password on stdin";
            return false;
        }
        for (unsigned char c : out->password)
            if (c < 0x09 || (c > 0x0d && c < 0x20) || c == 0x7f) {
                if (err)
                    *err = "password: invalid control characters on stdin";
                return false;
            }
        return true;
    }
    return read_credentials_file(cfg.credentials_file,
                                 cfg.security.allow_insecure_key_file_permissions, out, err);
}

struct ClientFlow::Impl {
    ClientConfig cfg;
    std::unique_ptr<gateway::GatewayClient> gw;
    std::unique_ptr<tunnel::TunnelClient> tunnel;
    std::unique_ptr<auth::AuthServer> auth_server;
    std::unique_ptr<auth::CallbackListener> callback;

    // Session-extension loop.
    std::thread ext_thread;
    std::atomic<bool> ext_stop{false};
    std::mutex ext_mu;
    std::condition_variable ext_cv;
    std::atomic<int> extensions{0};
    std::atomic<bool> stopped{false};
};

ClientFlow::ClientFlow(std::unique_ptr<Impl> impl) : impl_(std::move(impl)) {}

std::unique_ptr<ClientFlow> ClientFlow::create(const ClientConfig& cfg, std::string* err) {
    auto impl = std::make_unique<Impl>();
    impl->cfg = cfg;
    impl->gw = gateway::GatewayClient::create(cfg.security, cfg.gateway, cfg.cookie_dir, err);
    if (!impl->gw)
        return nullptr;
    return std::unique_ptr<ClientFlow>(new ClientFlow(std::move(impl)));
}

ClientFlow::~ClientFlow() {
    stop();
}

bool ClientFlow::run_posture(std::string* err) {
    const auto& pc = impl_->cfg.posture_check;
    if (pc.program.empty())
        return true;  // disabled
    GP_TRACE("posture: running '", pc.program, "' (timeout ", pc.timeout_ms, " ms)");
    posture::CheckResult r = posture::run_check(pc);
    if (r.spawn_failed) {
        if (err)
            *err = "posture check: failed to spawn '" + pc.program + "'";
        return false;
    }
    if (r.timed_out) {
        if (err)
            *err = "posture check timed out (fail closed)";
        return false;
    }
    if (!r.ok || r.exit_code != 0) {
        // Fail closed: no login, no session traffic. The child's stderr is NOT
        // spliced into the error string (it may contain sensitive host data).
        if (err)
            *err = "posture check failed with exit code " + std::to_string(r.exit_code);
        return false;
    }
    GP_TRACE("posture: ok (exit 0)");
    return true;
}

bool ClientFlow::run_direct(const Credentials& creds, TransportFactory transport,
                            std::string* err) {
    if (!run_posture(err))
        return false;
    GP_TRACE("flow: direct auth for user '", creds.username, "'");

    std::string step_err;
    GP_TRACE("flow: prelogin");
    if (!impl_->gw->prelogin(&step_err)) {
        if (err)
            *err = "prelogin: " + step_err;
        return false;
    }
    GP_TRACE("flow: login");
    if (!impl_->gw->login(creds.username, creds.password, &step_err)) {
        // step_err never contains credentials (guaranteed by GatewayClient).
        if (err)
            *err = "login: " + step_err;
        return false;
    }
    return finish_connect_and_tunnel(std::move(transport), err);
}

bool ClientFlow::run_browser_auth(TransportFactory transport, const ServersReadyHook& on_ready,
                                  std::string* err) {
    if (!run_posture(err))
        return false;

    std::string step_err;
    if (!impl_->gw->prelogin(&step_err)) {
        if (err)
            *err = "prelogin: " + step_err;
        return false;
    }

    // One-shot callback receiver (H-1): per-session token, size cap, deadline.
    impl_->callback = std::make_unique<auth::CallbackListener>(impl_->cfg.security);
    if (!impl_->callback->start(&step_err)) {
        if (err)
            *err = "callback listener: " + step_err;
        return false;
    }
    GP_TRACE("flow: browser auth: callback listener on 127.0.0.1:", impl_->callback->port(),
             " (one-shot path hidden)");

    // Local auth page server (H-2): tells the user where to authenticate.
    impl_->auth_server = std::make_unique<auth::AuthServer>(impl_->cfg.security);
    auth::AuthServerConfig as_cfg;
    as_cfg.bind_address = "127.0.0.1";
    as_cfg.port = 0;
    as_cfg.portal_display_url = impl_->cfg.gateway.base_url + "/sslvpn-login";
    if (!impl_->auth_server->start(as_cfg, &step_err)) {
        if (err)
            *err = "auth server: " + step_err;
        return false;
    }
    GP_TRACE("flow: browser auth: instructions page on 127.0.0.1:", impl_->auth_server->port(),
             " (one-shot URL hidden)");

    // Optional GUI host: the URL (with its one-time token) goes over STDIN,
    // never argv (H-3). Spawn failure is not fatal — the operator can open the
    // URL manually.
    if (!impl_->cfg.gui_program.empty()) {
        gui::GuiConfig g;
        g.program = impl_->cfg.gui_program;
        gui::launch(g, impl_->auth_server->url());
    }

    // Both servers are up: hand the URLs to the caller (the CLI prints them;
    // tests use this to drive a simulated browser) before blocking.
    if (on_ready) {
        std::string callback_url = "http://127.0.0.1:" + std::to_string(impl_->callback->port()) +
                                   impl_->callback->url_path();
        on_ready(impl_->auth_server->url(), callback_url);
    }

    auth::CallbackResult cb = impl_->callback->wait_for_callback();
    if (cb.status != auth::CallbackResult::Status::Delivered) {
        if (err)
            *err = "browser auth: " + cb.reason;
        return false;
    }
    GP_TRACE("flow: browser auth: callback received (", cb.payload.size(), " bytes)");

    // The GP browser plugin posts "globalprotectcallback:<payload>"; enforce the
    // marker so an arbitrary local page cannot inject a session.
    static const char kMarker[] = "globalprotectcallback:";
    if (cb.payload.compare(0, sizeof kMarker - 1, kMarker) != 0) {
        if (err)
            *err = "browser auth: callback payload missing the globalprotectcallback marker";
        return false;
    }
    std::string payload = cb.payload.substr(sizeof kMarker - 1);
    if (payload.empty()) {
        if (err)
            *err = "browser auth: empty callback payload";
        return false;
    }

    // The one-shot servers have done their job; stop them before the next hop.
    impl_->callback->stop();
    impl_->auth_server->stop();
    impl_->callback.reset();
    impl_->auth_server.reset();

    if (!impl_->gw->saml_login(payload, impl_->cfg.callback_return_path,
                               impl_->cfg.callback_field_name, &step_err)) {
        // step_err never contains the payload (guaranteed by GatewayClient).
        if (err)
            *err = "saml_login: " + step_err;
        return false;
    }
    return finish_connect_and_tunnel(std::move(transport), err);
}

bool ClientFlow::finish_connect_and_tunnel(TransportFactory transport, std::string* err) {
    std::string step_err;
    GP_TRACE("flow: connect");
    if (!impl_->gw->connect(&step_err)) {
        if (err)
            *err = "connect: " + step_err;
        return false;
    }

    if (impl_->cfg.want_tunnel) {
        auto transport_impl = transport ? transport() : nullptr;
        if (!transport_impl) {
            if (err)
                *err =
                    "tunnel: no transport backend available in this build "
                    "(libopenconnect not compiled in); use --no-tunnel to stop at the endpoint";
            return false;
        }
        impl_->tunnel =
            std::make_unique<tunnel::TunnelClient>(impl_->cfg.security, std::move(transport_impl));
        tunnel::TunnelConfig tcfg = impl_->cfg.tunnel_cfg;
        tcfg.endpoint_url = impl_->gw->tunnel_endpoint();
        std::string cookie_header =
            cookie_header_for(impl_->gw->store(), impl_->gw->tunnel_endpoint());
        GP_TRACE("flow: tunnel connect: ", tcfg.endpoint_url, " (proto=", tcfg.proto, ")");
        if (!impl_->tunnel->connect(tcfg, cookie_header, &step_err)) {
            if (err)
                *err = "tunnel: " + step_err;
            return false;
        }
    }

    // Session-extension loop: renews the portal session TTL until stop().
    impl_->ext_stop.store(false);
    impl_->extensions.store(0);
    GP_TRACE("flow: session extension loop started (every ", impl_->cfg.session_extend_interval_s,
             "s)");
    impl_->ext_thread = std::thread([this] { extension_loop(); });
    return true;
}

void ClientFlow::extension_loop() {
    auto interval = std::chrono::seconds(impl_->cfg.session_extend_interval_s);
    while (!impl_->ext_stop.load()) {
        {
            std::unique_lock<std::mutex> lk(impl_->ext_mu);
            impl_->ext_cv.wait_for(lk, interval, [&] { return impl_->ext_stop.load(); });
        }
        if (impl_->ext_stop.load())
            break;
        // Renewal failures are not fatal (the gateway may be briefly unreachable);
        // the loop retries on the next tick and ends only via stop().
        std::string err;
        if (impl_->gw->extend_session(&err)) {
            impl_->extensions.fetch_add(1);
        }
    }
}

void ClientFlow::stop() {
    if (!impl_)
        return;
    // Idempotent: the destructor calls stop() again after an explicit one.
    bool expected = false;
    if (!impl_->stopped.compare_exchange_strong(expected, true))
        return;
    impl_->ext_stop.store(true);
    impl_->ext_cv.notify_all();
    if (impl_->ext_thread.joinable())
        impl_->ext_thread.join();
    if (impl_->tunnel)
        impl_->tunnel->disconnect();
    if (impl_->callback)
        impl_->callback->stop();
    if (impl_->auth_server)
        impl_->auth_server->stop();
    GP_TRACE("flow: stopped after ", impl_->extensions.load(), " session renewal(s)");
}

const tunnel::SessionMetadata* ClientFlow::metadata() const {
    return impl_->tunnel ? impl_->tunnel->metadata() : nullptr;
}

const std::string& ClientFlow::tunnel_endpoint() const {
    return impl_->gw->tunnel_endpoint();
}

int ClientFlow::session_extensions() const {
    return impl_->extensions.load();
}

bool parse_gpclient_args(int argc, char** argv, ClientConfig& out, std::string* err) {
    // Shared security switches first (unknown args are ignored by from_args).
    if (!SecurityOptions::from_args(argc, argv, out.security, err))
        return false;

    auto fail = [&](const std::string& msg) {
        if (err)
            *err = msg;
        return false;
    };

    bool have_gateway = false;
    for (int i = 1; i < argc; ++i) {
        const std::string a = argv[i];
        auto next_value = [&](const char* what) -> const char* {
            if (i + 1 >= argc) {
                std::ostringstream oss;
                oss << "missing value for " << what;
                fail(oss.str());
                return nullptr;
            }
            return argv[++i];
        };

        if (a == "--gateway") {
            const char* v = next_value("--gateway");
            if (!v)
                return false;
            out.gateway.gateway_host = v;
            have_gateway = true;
            // Default origin unless --base-url was given explicitly.
            if (out.gateway.base_url.empty())
                out.gateway.base_url = std::string("https://") + v;
        } else if (a == "--base-url") {
            const char* v = next_value("--base-url");
            if (!v)
                return false;
            out.gateway.base_url = v;
        } else if (a == "--user") {
            const char* v = next_value("--user");
            if (!v)
                return false;
            out.username = v;
        } else if (a == "--password-on-stdin") {
            out.password_on_stdin = true;
        } else if (a == "--credentials-file") {
            const char* v = next_value("--credentials-file");
            if (!v)
                return false;
            out.credentials_file = v;
        } else if (a == "--cookie-dir") {
            const char* v = next_value("--cookie-dir");
            if (!v)
                return false;
            out.cookie_dir = v;
        } else if (a == "--tunnel-proto") {
            const char* v = next_value("--tunnel-proto");
            if (!v)
                return false;
            out.tunnel_cfg.proto = v;
        } else if (a == "--no-tunnel") {
            out.want_tunnel = false;
        } else if (a == "--browser-auth") {
            out.browser_auth = true;
        } else if (a == "--gui-program") {
            const char* v = next_value("--gui-program");
            if (!v)
                return false;
            out.gui_program = v;
        } else if (a == "--posture-program") {
            const char* v = next_value("--posture-program");
            if (!v)
                return false;
            out.posture_check.program = v;
        } else if (a == "--posture-timeout-ms") {
            const char* v = next_value("--posture-timeout-ms");
            if (!v)
                return false;
            char* end = nullptr;
            long ms = std::strtol(v, &end, 10);
            if (end == v || *end != '\0' || ms <= 0)
                return fail("invalid --posture-timeout-ms value: " + std::string(v));
            out.posture_check.timeout_ms = static_cast<int>(ms);
        } else if (a == "--extend-interval-s") {
            const char* v = next_value("--extend-interval-s");
            if (!v)
                return false;
            char* end = nullptr;
            long s = std::strtol(v, &end, 10);
            if (end == v || *end != '\0' || s < 1)
                return fail("invalid --extend-interval-s value: " + std::string(v));
            out.session_extend_interval_s = static_cast<int>(s);
        } else if (a == "--callback-return-path") {
            const char* v = next_value("--callback-return-path");
            if (!v)
                return false;
            out.callback_return_path = v;
        } else if (a == "--callback-field") {
            const char* v = next_value("--callback-field");
            if (!v)
                return false;
            out.callback_field_name = v;
        }
        // Unknown arguments are intentionally ignored (callers own their flags).
    }

    if (!have_gateway)
        return fail("missing required --gateway <host>");
    if (out.gateway.base_url.empty())
        return fail("missing gateway origin (--base-url)");
    if (out.password_on_stdin && !out.credentials_file.empty())
        return fail("--password-on-stdin and --credentials-file are mutually exclusive");

    // Direct-credential mode needs exactly one password source.
    if (!out.browser_auth) {
        if (out.password_on_stdin) {
            if (out.username.empty())
                return fail("--password-on-stdin requires --user <name>");
        } else if (out.credentials_file.empty()) {
            return fail("direct auth requires --password-on-stdin or --credentials-file");
        }
        // --credentials-file mode: the file itself holds username + password.
    }
    return true;
}

}  // namespace gp::client