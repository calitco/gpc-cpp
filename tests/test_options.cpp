#include <gp/security_options.h>

#include "test_framework.h"

using gp::SecurityOptions;

TEST(options, defaults_are_strict) {
    SecurityOptions o;
    CHECK(!o.allow_insecure_tls);
    CHECK(!o.pinned_gateway_cert_sha256.has_value());
    CHECK(!o.allow_remote_callback_bind);
    CHECK(!o.allow_insecure_key_file_permissions);
    CHECK(o.max_callback_payload_bytes == (1u << 20));
    auto notes = o.describe_policy();
    CHECK(notes.size() == 1);
    CHECK(notes[0].find("all defaults are strict") != std::string::npos);
}

TEST(options, parses_lenient_switches) {
    const char* argv[] = {"gp",
                          "--ignore-tls-errors",
                          "--pin-cert",
                          "AA:BB:CC",
                          "--allow-remote-callback",
                          "--max-callback-payload",
                          "4096",
                          "--callback-timeout-ms",
                          "1234",
                          "--allow-redirect-host",
                          "portal.example.com",
                          "--allow-insecure-key-file",
                          "--http-connect-timeout-s",
                          "5",
                          "--http-total-timeout-s",
                          "30",
                          "--max-http-response",
                          "8192",
                          "--ca-bundle",
                          "/etc/ssl/certs/ca.pem"};
    SecurityOptions o;
    std::string err;
    CHECK(SecurityOptions::from_args(20, const_cast<char**>(argv), o, &err));
    CHECK(o.allow_insecure_tls);
    CHECK(o.pinned_gateway_cert_sha256.has_value());
    CHECK(*o.pinned_gateway_cert_sha256 == "AA:BB:CC");
    CHECK(o.allow_remote_callback_bind);
    CHECK(o.max_callback_payload_bytes == 4096);
    CHECK(o.callback_timeout.count() == 1234);
    CHECK(o.allowed_redirect_hosts.size() == 1);
    CHECK(o.allowed_redirect_hosts[0] == "portal.example.com");
    CHECK(o.allow_insecure_key_file_permissions);
    CHECK(o.http_connect_timeout.count() == 5);
    CHECK(o.http_total_timeout.count() == 30);
    CHECK(o.max_http_response_bytes == 8192);
    CHECK(*o.ca_bundle_path == "/etc/ssl/certs/ca.pem");

    auto notes = o.describe_policy();
    bool saw_insecure = false, saw_remote = false;
    for (const auto& n : notes) {
        if (n.find("LENIENT") != std::string::npos &&
            n.find("--ignore-tls-errors") != std::string::npos)
            saw_insecure = true;
        if (n.find("--allow-remote-callback") != std::string::npos)
            saw_remote = true;
    }
    CHECK(saw_insecure);  // opt-ins must be visible in the policy summary
    CHECK(saw_remote);
}

TEST(options, rejects_malformed_values) {
    const char* argv[] = {"gp", "--max-callback-payload", "notanumber"};
    SecurityOptions o;
    std::string err;
    CHECK(!SecurityOptions::from_args(3, const_cast<char**>(argv), o, &err));
    CHECK(!err.empty());

    const char* argv2[] = {"gp", "--callback-timeout-ms"};  // missing value
    SecurityOptions o2;
    CHECK(!SecurityOptions::from_args(2, const_cast<char**>(argv2), o2, &err));
}

TEST(options, unknown_flags_are_ignored) {
    const char* argv[] = {"gp", "--some-other-tool-flag", "x"};
    SecurityOptions o;
    CHECK(SecurityOptions::from_args(3, const_cast<char**>(argv), o));
    CHECK(!o.allow_insecure_tls);
}

int main() {
    return gp::test::Registry::instance().run_all();
}
