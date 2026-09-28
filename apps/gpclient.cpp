// gpclient — GlobalProtect end-to-end client (Wave H).
//
// Flow: posture -> prelogin -> login (direct credentials or browser/IdP auth)
// -> portal connect -> tunnel endpoint. The session-extension loop keeps the
// portal session alive until Ctrl-C.
//
// Secrets: the password is read from stdin (--password-on-stdin) or a 0600
// file (--credentials-file), NEVER argv (H-3). In browser-auth mode no
// credentials are needed at all.
//
// Tunnel backend: this build does not compile in libopenconnect (upstream
// OpenConnect does not speak GlobalProtect without the reference project's
// patches). The client therefore authenticates, obtains the tunnel endpoint,
// and keeps the session alive; with --no-tunnel it stops right after the
// endpoint is obtained. A build with a TunnelTransport backend injects it via
// ClientFlow::run_*().
#include <chrono>
#include <csignal>
#include <iostream>
#include <memory>
#include <mutex>
#include <string>
#include <thread>

#include "gp/client_flow.h"
#include "gp/trace.h"

namespace {

volatile std::sig_atomic_t g_stop = 0;
void on_signal(int) {
    g_stop = 1;
}

void print_usage() {
    std::cout
        << "usage: gpclient --gateway <host> [options]\n"
           "\n"
           "auth mode (pick one):\n"
           "  --user <name> --password-on-stdin   direct credentials; password = one line on "
           "stdin\n"
           "  --credentials-file <path>           direct credentials from a 0600 file "
           "(username\\npassword\\n)\n"
           "  --browser-auth                      IdP/browser flow via the local callback "
           "listener\n"
           "\n"
           "options:\n"
           "  --base-url <url>                    gateway origin (default https://<host>)\n"
           "  --cookie-dir <dir>                  session cookie store (default "
           "/tmp/gpclient-cookies)\n"
           "  --tunnel-proto <ipsec|dtls>         tunnel protocol (default ipsec)\n"
           "  --no-tunnel                         stop after obtaining the tunnel endpoint\n"
           "  --gui-program <path>                GUI host for browser auth (URL on its stdin)\n"
           "  --posture-program <path>            posture check binary (fail closed on non-zero "
           "exit)\n"
           "  --posture-timeout-ms <n>            posture deadline (default 30000)\n"
           "  --extend-interval-s <n>             session renewal interval (default 300, min 1)\n"
           "  --callback-return-path <path>       where the IdP payload is POSTed (default "
           "/sslvpn-login)\n"
           "  --callback-field <name>             form field for the IdP payload (default "
           "SAMLResponse)\n"
           "  --verbose / -v                      trace the process to stderr (metadata only:\n"
           "                                       stages, URL paths, HTTP statuses; never "
           "credentials)\n"

           "\n"
           "security switches (shared):\n"
           "  --pin-cert <sha256>                 pin the gateway leaf certificate\n"
           "  --ca-bundle <path>                  CA bundle override (PEM)\n"
           "  --check-crl / --crl-bundle <path>   require valid CRLs (strictening)\n"
           "  --ignore-tls-errors                 LENIENT: disable TLS validation (audited in "
           "logs)\n"
           "  --allow-remote-callback             LENIENT: allow non-loopback callback bind\n"
           "  --allow-insecure-key-file           LENIENT: relax 0600 checks on secret files\n"
           "  --http-connect-timeout-s <n> / --http-total-timeout-s <n> / --max-http-response "
           "<n>\n";
}

// This build has no compiled-in tunnel backend; the factory reports that via
// nullptr and ClientFlow fails with an explicit, actionable message unless
// --no-tunnel was given.
gp::client::ClientFlow::TransportFactory no_backend() {
    return [] { return std::unique_ptr<gp::tunnel::TunnelTransport>(nullptr); };
}

}  // namespace

int main(int argc, char** argv) {
    if (argc > 1 && (std::string(argv[1]) == "--help" || std::string(argv[1]) == "-h")) {
        print_usage();
        return 0;
    }

    // --verbose installs the process-wide trace sink. Lines are metadata only
    // (M-3); a mutex keeps lines atomic across the flow/extension threads.
    for (int i = 1; i < argc; ++i) {
        const std::string a = argv[i];
        if (a == "--verbose" || a == "-v") {
            static std::mutex trace_mu;
            gp::trace::set_sink([&](const std::string& line) {
                std::lock_guard<std::mutex> lk(trace_mu);
                std::cerr << "[trace] " << line << "\n";
            });
            break;
        }
    }

    gp::client::ClientConfig cfg;
    std::string err;
    if (!gp::client::parse_gpclient_args(argc, argv, cfg, &err)) {
        std::cerr << "gpclient: " << err << "\n";
        return 2;
    }

    // Report exactly which security guarantees were weakened (or hardened).
    for (const auto& note : cfg.security.describe_policy())
        std::cout << "[policy] " << note << "\n";

    auto flow = gp::client::ClientFlow::create(cfg, &err);
    if (!flow) {
        std::cerr << "gpclient: " << err << "\n";
        return 1;
    }

    ::signal(SIGINT, on_signal);
    ::signal(SIGTERM, on_signal);

    bool ok;
    if (cfg.browser_auth) {
        std::cout << "[auth] browser mode — waiting for the one-shot callback...\n";
        ok = flow->run_browser_auth(
            no_backend(),
            [](const std::string& auth_page_url, const std::string& callback_url) {
                std::cout << "[auth] open in your browser: " << auth_page_url << "\n"
                          << "[auth] (the callback listener expects the GP plugin at "
                          << callback_url << ")\n";
            },
            &err);
    } else {
        gp::client::Credentials creds;
        if (!gp::client::read_direct_credentials(cfg, &creds, &err)) {
            std::cerr << "gpclient: " << err << "\n";
            return 1;
        }
        ok = flow->run_direct(creds, no_backend(), &err);
    }
    if (!ok) {
        std::cerr << "gpclient: " << err << "\n";
        flow->stop();
        return 1;
    }

    std::cout << "[tunnel] endpoint: " << flow->tunnel_endpoint() << "\n";
    if (const auto* m = flow->metadata()) {
        if (m->present) {
            std::cout << "[session] user=" << m->user;
            if (m->user_expires.has_value())
                std::cout << " expires=" << *m->user_expires;
            std::cout << "\n";
        }
    }
    std::cout << "[gpclient] session active — press Ctrl-C to disconnect\n";

    while (!g_stop)
        std::this_thread::sleep_for(std::chrono::milliseconds(200));

    std::cout << "\n[gpclient] shutting down (" << flow->session_extensions()
              << " session renewals)\n";
    flow->stop();
    return 0;
}