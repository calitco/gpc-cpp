// Tests for Wave G: tunnel endpoint validation, session-metadata parsing
// (safe port of patch 0005), and the certificate policy wiring (C-1 at
// tunnel level) through a fake transport. Real X.509 certificates from the
// shared test factory are used — no mock verifier needed for the policy.
#include <gp/cert_policy.h>
#include <gp/tunnel_client.h>
#include <openssl/sha.h>
#include <unistd.h>

#include <memory>
#include <string>
#include <vector>

#include "cert_test_util.h"
#include "test_framework.h"

using gp::SecurityOptions;
using namespace gp::tunnel;
namespace certtest = gp::certtest;

namespace {

std::string sha256_hex_of(const std::vector<unsigned char>& der) {
    unsigned char digest[32];
    SHA256(der.data(), der.size(), digest);
    static const char* h = "0123456789abcdef";
    std::string out(64, '0');
    for (int i = 0; i < 32; ++i) {
        out[2 * i] = h[digest[i] >> 4];
        out[2 * i + 1] = h[digest[i] & 0xf];
    }
    return out;
}

// Fake tunnel backend: presents a configurable certificate, records calls.
class FakeTransport : public TunnelTransport {
   public:
    PresentedCert present{};
    bool present_cert = true;  // false => no handshake certificate at all
    std::string metadata_xml;
    bool fail_connect = false;
    int connect_calls = 0;
    int disconnect_calls = 0;
    std::string last_cookie_header;
    std::string last_endpoint;

    bool connect(const TunnelConfig& cfg, const std::string& cookie_header, CertCallback on_cert,
                 std::string* err) override {
        ++connect_calls;
        last_cookie_header = cookie_header;
        last_endpoint = cfg.endpoint_url;
        if (present_cert && !on_cert(present)) {
            if (err)
                *err = "certificate rejected by policy";
            return false;
        }
        if (fail_connect) {
            if (err)
                *err = "simulated transport failure";
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

// CA + leaf (SAN gw.test) + CA bundle file, mirroring the cert policy tests.
struct TunnelFixture {
    certtest::TestCert ca;
    std::string bundle_path;
    certtest::TestCert good_leaf;   // SAN: gw.test
    certtest::TestCert rogue_leaf;  // self-signed, NOT in the bundle

    TunnelFixture() {
        certtest::make_ca(ca, "Tunnel Test CA");
        char tmpl[] = "/tmp/gp_tunnel_ca_XXXXXX";
        int fd = mkstemp(tmpl);
        REQUIRE(fd >= 0);
        ::close(fd);
        bundle_path = tmpl;
        certtest::write_ca_pem(ca, bundle_path);

        certtest::make_leaf(good_leaf, ca, "gw.test", {"gw.test"});
        // Self-signed rogue: its own subject == issuer, not in any bundle.
        certtest::make_ca(rogue_leaf, "Rogue Tunnel CA");
    }
    ~TunnelFixture() { ::unlink(bundle_path.c_str()); }

    SecurityOptions opts_with_bundle() const {
        SecurityOptions o;
        o.ca_bundle_path = bundle_path;
        return o;
    }
};

}  // namespace

// ---------------------------------------------------------------------------
// Endpoint URL validation
// ---------------------------------------------------------------------------

TEST(tunnel, config_rejects_empty_url) {
    TunnelConfig c;
    std::string err;
    CHECK(!validate_tunnel_config(c, &err));
    CHECK(!err.empty());
}

TEST(tunnel, config_rejects_http_on_non_loopback) {
    TunnelConfig c{"http://gw.example.com/tunnel/start", "ipsec"};
    std::string err;
    CHECK(!validate_tunnel_config(c, &err));
    CHECK(err.find("https") != std::string::npos);
}

TEST(tunnel, config_allows_http_loopback_for_tests) {
    TunnelConfig c{"http://127.0.0.1:8443/tunnel/start", "ipsec"};
    CHECK(validate_tunnel_config(c));
}

TEST(tunnel, config_accepts_https_with_port_and_query) {
    TunnelConfig c{"https://gw.example.com:8443/tunnel/start?proto=ipsec&key=abc", "dtls"};
    CHECK(validate_tunnel_config(c));
}

TEST(tunnel, config_rejects_embedded_credentials) {
    TunnelConfig c{"https://user:pass@gw.example.com/tunnel/start", "ipsec"};
    std::string err;
    CHECK(!validate_tunnel_config(c, &err));
    CHECK(err.find("credentials") != std::string::npos);
}

TEST(tunnel, config_rejects_control_characters) {
    TunnelConfig c{"https://gw.example.com/tunnel/start\r\nX-Injected: 1", "ipsec"};
    std::string err;
    CHECK(!validate_tunnel_config(c, &err));
    CHECK(err.find("control") != std::string::npos);
}

TEST(tunnel, config_rejects_malformed_url) {
    TunnelConfig c{"https://", "ipsec"};
    std::string err;
    CHECK(!validate_tunnel_config(c, &err));
    TunnelConfig d{"not-a-url", "ipsec"};
    CHECK(!validate_tunnel_config(d, &err));
}

TEST(tunnel, config_rejects_unknown_proto) {
    TunnelConfig c{"https://gw.example.com/tunnel/start", "gre"};
    std::string err;
    CHECK(!validate_tunnel_config(c, &err));
    CHECK(err.find("protocol") != std::string::npos);
}

// ---------------------------------------------------------------------------
// Session metadata parsing (safe port of patch 0005)
// ---------------------------------------------------------------------------

TEST(tunnel, metadata_empty_document_means_absent) {
    SessionMetadata m;
    std::string err;
    CHECK(parse_session_metadata("", 1 << 20, &m, &err));
    CHECK(!m.present);
    CHECK(!m.user_expires.has_value());
}

TEST(tunnel, metadata_parses_user_and_dash_expires) {
    SessionMetadata m;
    std::string err;
    const char* doc =
        "<tunnel-info><user user-expires=\"2030-01-01T00:00:00Z\">alice</user></tunnel-info>";
    CHECK(parse_session_metadata(doc, 1 << 20, &m, &err));
    CHECK(m.present);
    CHECK_EQ(m.user, std::string("alice"));
    REQUIRE(m.user_expires.has_value());
    CHECK_EQ(*m.user_expires, std::string("2030-01-01T00:00:00Z"));
}

TEST(tunnel, metadata_parses_underscore_expires_variant) {
    SessionMetadata m;
    const char* doc = "<x><user user_expires=\"1798761600\">bob</user></x>";
    CHECK(parse_session_metadata(doc, 1 << 20, &m));
    CHECK(m.present);
    CHECK_EQ(m.user, std::string("bob"));
    REQUIRE(m.user_expires.has_value());
    CHECK_EQ(*m.user_expires, std::string("1798761600"));
}

TEST(tunnel, metadata_missing_both_attrs_is_safe_not_garbage) {
    // The audit's "verified non-issue" scenario: neither attribute present.
    // Must yield no expires value — never an uninitialized read.
    SessionMetadata m;
    const char* doc = "<x><user>carol</user></x>";
    CHECK(parse_session_metadata(doc, 1 << 20, &m));
    CHECK(m.present);
    CHECK_EQ(m.user, std::string("carol"));
    CHECK(!m.user_expires.has_value());
}

TEST(tunnel, metadata_document_without_user_element) {
    SessionMetadata m;
    const char* doc = "<x><other>1</other></x>";
    CHECK(parse_session_metadata(doc, 1 << 20, &m));
    CHECK(!m.present);
}

TEST(tunnel, metadata_rejects_doctype) {
    SessionMetadata m;
    std::string err;
    const char* doc =
        "<?xml version=\"1.0\"?>"
        "<!DOCTYPE x [<!ENTITY r SYSTEM \"file:///etc/passwd\">]>"
        "<x><user>&r;</user></x>";
    CHECK(!parse_session_metadata(doc, 1 << 20, &m, &err));
}

TEST(tunnel, metadata_rejects_oversized_document) {
    SessionMetadata m;
    std::string big(4096, 'a');  // exceeds the 64-byte cap below
    CHECK(!parse_session_metadata(big, 64, &m));
}

// ---------------------------------------------------------------------------
// CertPolicyCallback (C-1 at tunnel level)
// ---------------------------------------------------------------------------

TEST(tunnel, cert_callback_accepts_valid_chain_and_host) {
    TunnelFixture f;
    auto cb = std::make_unique<CertPolicyCallback>(
        f.opts_with_bundle(),
        std::make_unique<gp::cert::OpenSslCertificateVerifier>(f.opts_with_bundle()));
    PresentedCert pc{f.good_leaf.der, {}, "gw.test"};
    auto r = (*cb)(pc);
    CHECK(r.accept);
    CHECK(!r.reason.empty());
}

TEST(tunnel, cert_callback_rejects_hostname_mismatch) {
    TunnelFixture f;
    auto cb = std::make_unique<CertPolicyCallback>(
        f.opts_with_bundle(),
        std::make_unique<gp::cert::OpenSslCertificateVerifier>(f.opts_with_bundle()));
    PresentedCert pc{f.good_leaf.der, {}, "other.test"};
    auto r = (*cb)(pc);
    CHECK(!r.accept);
    CHECK(r.reason.find("hostname") != std::string::npos ||
          r.reason.find("mismatch") != std::string::npos);
}

TEST(tunnel, cert_callback_rejects_untrusted_cert_by_default) {
    // The C-1 regression: the old shim accepted this unconditionally.
    TunnelFixture f;
    auto cb = std::make_unique<CertPolicyCallback>(
        f.opts_with_bundle(),
        std::make_unique<gp::cert::OpenSslCertificateVerifier>(f.opts_with_bundle()));
    PresentedCert pc{f.rogue_leaf.der, {}, "gw.test"};
    auto r = (*cb)(pc);
    CHECK(!r.accept);
}

TEST(tunnel, cert_callback_insecure_optin_accepts_but_is_audited) {
    TunnelFixture f;
    SecurityOptions o = f.opts_with_bundle();
    o.allow_insecure_tls = true;
    auto cb = std::make_unique<CertPolicyCallback>(
        o, std::make_unique<gp::cert::OpenSslCertificateVerifier>(o));
    PresentedCert pc{f.rogue_leaf.der, {}, "gw.test"};
    auto r = (*cb)(pc);
    CHECK(r.accept);
    CHECK(r.reason.find("INSECURE OPT-IN") != std::string::npos);
}

TEST(tunnel, cert_callback_pinning_enforced) {
    TunnelFixture f;
    SecurityOptions o = f.opts_with_bundle();
    o.pinned_gateway_cert_sha256 = sha256_hex_of(f.good_leaf.der);
    auto cb_ok = std::make_unique<CertPolicyCallback>(
        o, std::make_unique<gp::cert::OpenSslCertificateVerifier>(o));
    PresentedCert good{f.good_leaf.der, {}, "gw.test"};
    CHECK((*cb_ok)(good).accept);

    SecurityOptions o2 = f.opts_with_bundle();
    o2.pinned_gateway_cert_sha256 = std::string(64, '0');  // wrong pin
    auto cb_bad = std::make_unique<CertPolicyCallback>(
        o2, std::make_unique<gp::cert::OpenSslCertificateVerifier>(o2));
    auto r = (*cb_bad)(good);
    CHECK(!r.accept);
    CHECK(r.reason.find("pin") != std::string::npos ||
          r.reason.find("fingerprint") != std::string::npos);
}

// ---------------------------------------------------------------------------
// TunnelClient orchestration
// ---------------------------------------------------------------------------

TEST(tunnel, client_connects_with_good_cert_and_metadata) {
    TunnelFixture f;
    auto t = std::make_unique<FakeTransport>();
    t->present.leaf_der = f.good_leaf.der;
    t->present.host_or_ip = "gw.test";
    t->metadata_xml =
        "<tunnel-info><user user-expires=\"2030-01-01T00:00:00Z\">alice</user></tunnel-info>";

    TunnelClient client(f.opts_with_bundle(), std::move(t));
    TunnelConfig cfg{"https://gw.test/tunnel/start?proto=ipsec", "ipsec"};
    std::string err;
    CHECK(client.connect(cfg, "IKEY=abc123", &err));
    CHECK(client.connected());
    CHECK_EQ(client.cert_decisions().size(), size_t(1));
    CHECK(client.cert_decisions()[0].first);
    REQUIRE(client.metadata());
    CHECK(client.metadata()->present);
    CHECK_EQ(client.metadata()->user, std::string("alice"));
    client.disconnect();
    CHECK(!client.connected());
}

TEST(tunnel, client_rejects_bad_cert_and_reports_reason) {
    TunnelFixture f;
    auto t = std::make_unique<FakeTransport>();
    t->present.leaf_der = f.rogue_leaf.der;
    t->present.host_or_ip = "gw.test";

    TunnelClient client(f.opts_with_bundle(), std::move(t));
    TunnelConfig cfg{"https://gw.test/tunnel/start", "ipsec"};
    std::string err;
    CHECK(!client.connect(cfg, "IKEY=abc123", &err));
    CHECK(!client.connected());
    CHECK_EQ(client.cert_decisions().size(), size_t(1));
    CHECK(!client.cert_decisions()[0].first);
    // The rejection reason must surface in the error (auditable, no blanket accept).
    CHECK(err.find("rejected") != std::string::npos || err.find("chain") != std::string::npos);
}

TEST(tunnel, client_insecure_optin_connects_with_bad_cert) {
    TunnelFixture f;
    SecurityOptions o = f.opts_with_bundle();
    o.allow_insecure_tls = true;
    auto t = std::make_unique<FakeTransport>();
    t->present.leaf_der = f.rogue_leaf.der;
    t->present.host_or_ip = "gw.test";

    TunnelClient client(o, std::move(t));
    TunnelConfig cfg{"https://gw.test/tunnel/start", "ipsec"};
    CHECK(client.connect(cfg, ""));
    REQUIRE(!client.cert_decisions().empty());
    CHECK(client.cert_decisions()[0].first);
    CHECK(client.cert_decisions()[0].second.find("INSECURE OPT-IN") != std::string::npos);
}

TEST(tunnel, client_rejects_invalid_config_before_transport) {
    TunnelFixture f;
    auto t = std::make_unique<FakeTransport>();
    FakeTransport* raw = t.get();
    TunnelClient client(f.opts_with_bundle(), std::move(t));
    TunnelConfig cfg{"http://gw.test/tunnel/start", "ipsec"};  // http, non-loopback
    std::string err;
    CHECK(!client.connect(cfg, "", &err));
    CHECK_EQ(raw->connect_calls, 0);  // transport never touched
}

TEST(tunnel, client_double_connect_refused) {
    TunnelFixture f;
    auto t = std::make_unique<FakeTransport>();
    t->present.leaf_der = f.good_leaf.der;
    t->present.host_or_ip = "gw.test";
    TunnelClient client(f.opts_with_bundle(), std::move(t));
    TunnelConfig cfg{"https://gw.test/tunnel/start", "ipsec"};
    CHECK(client.connect(cfg, ""));
    std::string err;
    CHECK(!client.connect(cfg, "", &err));
    CHECK(err.find("already") != std::string::npos);
}

TEST(tunnel, client_disconnect_idempotent_and_raii) {
    TunnelFixture f;
    auto t = std::make_unique<FakeTransport>();
    FakeTransport* raw = t.get();
    t->present.leaf_der = f.good_leaf.der;
    t->present.host_or_ip = "gw.test";
    {
        TunnelClient client(f.opts_with_bundle(), std::move(t));
        TunnelConfig cfg{"https://gw.test/tunnel/start", "ipsec"};
        CHECK(client.connect(cfg, ""));
        client.disconnect();
        client.disconnect();  // second call is a no-op
        CHECK_EQ(raw->disconnect_calls, 1);
    }
    // Destructor of the (already disconnected) client must not double-disconnect.
    CHECK_EQ(raw->disconnect_calls, 1);
}

TEST(tunnel, client_malformed_metadata_surfaces_error_not_fatal) {
    TunnelFixture f;
    auto t = std::make_unique<FakeTransport>();
    t->present.leaf_der = f.good_leaf.der;
    t->present.host_or_ip = "gw.test";
    t->metadata_xml = "<tunnel-info><user>broken</tunnel-info>";  // unbalanced

    TunnelClient client(f.opts_with_bundle(), std::move(t));
    TunnelConfig cfg{"https://gw.test/tunnel/start", "ipsec"};
    CHECK(client.connect(cfg, ""));  // tunnel itself is fine
    CHECK(!client.metadata_error().empty());
    REQUIRE(client.metadata());
    CHECK(!client.metadata()->present);
}

TEST(tunnel, concurrent_clients_do_not_share_state) {
    // The old C shim kept global state; two TunnelClients must be independent.
    TunnelFixture f;
    auto t1 = std::make_unique<FakeTransport>();
    t1->present.leaf_der = f.good_leaf.der;
    t1->present.host_or_ip = "gw.test";
    auto t2 = std::make_unique<FakeTransport>();
    t2->present.leaf_der = f.rogue_leaf.der;  // client 2 gets REJECTED
    t2->present.host_or_ip = "gw.test";

    TunnelClient c1(f.opts_with_bundle(), std::move(t1));
    TunnelClient c2(f.opts_with_bundle(), std::move(t2));
    TunnelConfig cfg{"https://gw.test/tunnel/start", "ipsec"};

    CHECK(c1.connect(cfg, ""));
    std::string err;
    CHECK(!c2.connect(cfg, "", &err));
    CHECK(c1.connected());  // c1 unaffected by c2's rejection
    CHECK(!c2.connected());
    REQUIRE(c1.metadata());
    CHECK(!c1.metadata()->present);  // t1 sent no metadata
}

int main() {
    return gp::test::Registry::instance().run_all();
}