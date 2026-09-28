// Global security policy switches for the C++ reimplementation.
//
// Design rule (fixes C-1/H-1/H-2/M-1): every *lenient* behavior is OFF by
// default and must be explicitly enabled via a named switch. The defaults
// implement the secure behavior; the old Rust code's lenient defaults are
// only reachable when the operator opts in, and each opt-in is reported by
// describe_policy() so it shows up in logs.
#pragma once

#include <chrono>
#include <cstddef>
#include <optional>
#include <string>
#include <vector>

namespace gp {

struct SecurityOptions {
    // ---- TLS / tunnel (fixes C-1) ------------------------------------------
    // Default: STRICT validation (chain + hostname + expiry). The old shim
    // accepted every failed certificate unconditionally; that is now only
    // possible with this explicit opt-in.
    bool allow_insecure_tls = false;  // switch: --ignore-tls-errors

    // Optional SHA-256 fingerprint pin of the gateway leaf certificate
    // (hex, with or without ':' separators). When set, validation succeeds
    // only if BOTH chain validation AND the pin match.
    std::optional<std::string> pinned_gateway_cert_sha256;  // --pin-cert

    // Optional CA bundle (PEM) to verify against instead of/in addition to
    // the system trust store.
    std::optional<std::string> ca_bundle_path;  // --ca-bundle

    // Optional CRL checking for TLS connections (portal + tunnel). When set,
    // the verifier REQUIRES a valid CRL for every non-root certificate in the
    // chain; if no CRL is available, validation fails closed. CRLs are loaded
    // from crl_bundle_path (PEM) when provided, otherwise only CRLs already
    // present in the trust store are used. This STRICTENS validation — it is
    // never a lenient switch.
    bool check_crl = false;                      // switch: --check-crl
    std::optional<std::string> crl_bundle_path;  // --crl-bundle

    // ---- Browser-auth callback listener (fixes H-1) -------------------------
    // Per-session token in the callback URL path is ALWAYS enforced (there is
    // no switch to disable it: it is what makes local injection impossible).
    std::size_t max_callback_payload_bytes = 1u << 20;    // 1 MiB default cap
    std::chrono::milliseconds callback_timeout{300'000};  // 5 min overall

    // ---- Browser-auth page server (fixes H-2) -------------------------------
    // Default: bind to 127.0.0.1 only. Binding to a LAN address requires this
    // explicit opt-in (Remote mode).
    bool allow_remote_callback_bind = false;                 // switch: --allow-remote-callback
    std::size_t max_auth_server_requests = 16;               // total request cap
    std::chrono::milliseconds auth_server_timeout{300'000};  // lifetime
    // If set, redirect targets must belong to one of these hosts.
    std::vector<std::string> allowed_redirect_hosts;  // --allow-redirect-host

    // ---- Service API key (fixes M-1) ----------------------------------------
    // The key is ALWAYS freshly generated from a CSPRNG. There is no hardcoded
    // fallback. Operators may provide their own key via a 0600 file; loading
    // from a world-readable file is refused unless this is set.
    bool allow_insecure_key_file_permissions = false;  // --allow-insecure-key-file

    // ---- HTTP client (fixes M-2) --------------------------------------------
    std::chrono::seconds http_connect_timeout{10};
    std::chrono::seconds http_total_timeout{60};
    std::size_t max_http_response_bytes = 16u << 20;  // 16 MiB cap

    // ---- Logging (fixes H-3) -------------------------------------------------
    // Log files are always created 0600. Raw auth payloads are never logged;
    // only redacted summaries. No switch to disable this.

    // Parse a subset of CLI switches into options. Unknown args are ignored so
    // callers can mix in their own flags. Returns false on malformed values.
    static bool from_args(int argc, char** argv, SecurityOptions& out, std::string* err = nullptr);

    // Human-readable summary of every non-default (lenient) setting. Used to
    // log exactly which security guarantees were weakened and how.
    std::vector<std::string> describe_policy() const;
};

}  // namespace gp
