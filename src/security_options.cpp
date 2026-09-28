#include "gp/security_options.h"

#include <cstdlib>
#include <cstring>
#include <sstream>

namespace gp {

namespace {
bool parse_size(const char* s, std::size_t& out) {
    if (!s || !*s)
        return false;
    errno = 0;
    char* end = nullptr;
    unsigned long long v = std::strtoull(s, &end, 10);
    if (errno != 0 || end == s || *end != '\0')
        return false;
    out = static_cast<std::size_t>(v);
    return true;
}

bool parse_ms(const char* s, std::chrono::milliseconds& out) {
    std::size_t v = 0;
    if (!parse_size(s, v))
        return false;
    out = std::chrono::milliseconds(v);
    return true;
}

bool parse_seconds(const char* s, std::chrono::seconds& out) {
    std::size_t v = 0;
    if (!parse_size(s, v))
        return false;
    out = std::chrono::seconds(v);
    return true;
}
}  // namespace

bool SecurityOptions::from_args(int argc, char** argv, SecurityOptions& out, std::string* err) {
    auto fail = [&](const std::string& msg) {
        if (err)
            *err = msg;
        return false;
    };

    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];
        auto next_value = [&](const char* what) -> const char* {
            if (i + 1 >= argc) {
                std::ostringstream oss;
                oss << "missing value for " << what;
                fail(oss.str());
                return nullptr;
            }
            return argv[++i];
        };

        if (arg == "--ignore-tls-errors") {
            out.allow_insecure_tls = true;
        } else if (arg == "--pin-cert") {
            const char* v = next_value("--pin-cert");
            if (!v)
                return false;
            out.pinned_gateway_cert_sha256 = v;
        } else if (arg == "--ca-bundle") {
            const char* v = next_value("--ca-bundle");
            if (!v)
                return false;
            out.ca_bundle_path = v;
        } else if (arg == "--check-crl") {
            out.check_crl = true;
        } else if (arg == "--crl-bundle") {
            const char* v = next_value("--crl-bundle");
            if (!v)
                return false;
            out.crl_bundle_path = v;
        } else if (arg == "--allow-remote-callback") {
            out.allow_remote_callback_bind = true;
        } else if (arg == "--max-callback-payload") {
            const char* v = next_value("--max-callback-payload");
            if (!v)
                return false;
            if (!parse_size(v, out.max_callback_payload_bytes))
                return fail("invalid --max-callback-payload value: " + std::string(v));
        } else if (arg == "--callback-timeout-ms") {
            const char* v = next_value("--callback-timeout-ms");
            if (!v)
                return false;
            if (!parse_ms(v, out.callback_timeout))
                return fail("invalid --callback-timeout-ms value: " + std::string(v));
        } else if (arg == "--allow-redirect-host") {
            const char* v = next_value("--allow-redirect-host");
            if (!v)
                return false;
            out.allowed_redirect_hosts.push_back(v);
        } else if (arg == "--allow-insecure-key-file") {
            out.allow_insecure_key_file_permissions = true;
        } else if (arg == "--http-connect-timeout-s") {
            const char* v = next_value("--http-connect-timeout-s");
            if (!v)
                return false;
            if (!parse_seconds(v, out.http_connect_timeout))
                return fail("invalid --http-connect-timeout-s value: " + std::string(v));
        } else if (arg == "--http-total-timeout-s") {
            const char* v = next_value("--http-total-timeout-s");
            if (!v)
                return false;
            if (!parse_seconds(v, out.http_total_timeout))
                return fail("invalid --http-total-timeout-s value: " + std::string(v));
        } else if (arg == "--max-http-response") {
            const char* v = next_value("--max-http-response");
            if (!v)
                return false;
            if (!parse_size(v, out.max_http_response_bytes))
                return fail("invalid --max-http-response value: " + std::string(v));
        }
        // Unknown arguments are intentionally ignored (callers own their flags).
    }
    return true;
}

std::vector<std::string> SecurityOptions::describe_policy() const {
    std::vector<std::string> notes;
    if (allow_insecure_tls)
        notes.push_back(
            "LENIENT: TLS certificate validation disabled "
            "(--ignore-tls-errors); gateway identity is NOT verified");
    if (pinned_gateway_cert_sha256.has_value())
        notes.push_back("STRICT+: gateway certificate pinned to SHA-256 " +
                        *pinned_gateway_cert_sha256);
    if (ca_bundle_path.has_value())
        notes.push_back("CA bundle override: " + *ca_bundle_path);
    if (check_crl) {
        notes.push_back(
            "STRICT+: CRL checking enabled (--check-crl); chains without a "
            "valid CRL are rejected" +
            (crl_bundle_path.has_value() ? " (CRL bundle: " + *crl_bundle_path + ")" : ""));
    }
    if (allow_remote_callback_bind)
        notes.push_back(
            "LENIENT: auth callback server may bind to a non-loopback "
            "address (--allow-remote-callback)");
    if (allow_insecure_key_file_permissions)
        notes.push_back(
            "LENIENT: service key file permission checks relaxed "
            "(--allow-insecure-key-file)");
    if (!allowed_redirect_hosts.empty()) {
        std::string hosts;
        for (auto& h : allowed_redirect_hosts)
            hosts += h + ",";
        notes.push_back("redirect host allowlist active: " + hosts);
    }
    if (notes.empty())
        notes.push_back("all defaults are strict (no lenient switches enabled)");
    return notes;
}

}  // namespace gp
