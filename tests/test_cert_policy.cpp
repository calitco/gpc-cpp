// Regression tests for finding C-1: the old shim accepted EVERY failed
// gateway certificate. The default policy must REJECT, and acceptance of a
// bad cert is only possible through the explicit --ignore-tls-errors switch
// (and even then it is logged).
#include <gp/cert_policy.h>
#include <gp/random.h>
#include <unistd.h>

#include "cert_test_util.h"
#include "test_framework.h"

using namespace gp;
using namespace gp::cert;

namespace {

struct Fixture {
    certtest::TestCert ca;
    std::string bundle_path;
    certtest::TestCert good_leaf;     // SAN: gateway.example.com
    certtest::TestCert expired_leaf;  // valid chain, notAfter in the past
    certtest::TestCert rogue_ca;      // NOT in the trust bundle
    certtest::TestCert rogue_leaf;    // signed by rogue_ca

    Fixture() {
        certtest::make_ca(ca, "GP Test CA");
        char tmpl[] = "/tmp/gp_cert_test_XXXXXX";
        int fd = mkstemp(tmpl);
        REQUIRE(fd >= 0);
        close(fd);
        bundle_path = tmpl;
        certtest::write_ca_pem(ca, bundle_path);

        auto now = std::chrono::system_clock::now();
        certtest::make_leaf(good_leaf, ca, "gateway.example.com", {"gateway.example.com"});
        certtest::make_leaf(expired_leaf, ca, "gateway.example.com", {"gateway.example.com"},
                            now - std::chrono::hours(48), now - std::chrono::hours(24));
        certtest::make_ca(rogue_ca, "GP Rogue CA");
        certtest::make_leaf(rogue_leaf, rogue_ca, "gateway.example.com", {"gateway.example.com"});
    }

    ~Fixture() { std::remove(bundle_path.c_str()); }
};

Fixture& fx() {
    static Fixture f;
    return f;
}

SecurityOptions opts_with_bundle() {
    SecurityOptions o;
    o.ca_bundle_path = fx().bundle_path;
    return o;
}

}  // namespace

TEST(cert, strict_accepts_valid_chain_and_host) {
    auto o = opts_with_bundle();
    OpenSslCertificateVerifier v(o);
    Decision d = evaluate_peer_cert(o, v, fx().good_leaf.der, {}, "gateway.example.com");
    CHECK(d.accept);
    CHECK(d.reason.find("verified") != std::string::npos);
}

TEST(cert, strict_rejects_hostname_mismatch) {
    auto o = opts_with_bundle();
    OpenSslCertificateVerifier v(o);
    Decision d = evaluate_peer_cert(o, v, fx().good_leaf.der, {}, "evil.example.com");
    CHECK(!d.accept);
    CHECK(d.reason.find("hostname mismatch") != std::string::npos);
}

TEST(cert, strict_rejects_expired_certificate) {
    auto o = opts_with_bundle();
    OpenSslCertificateVerifier v(o);
    Decision d = evaluate_peer_cert(o, v, fx().expired_leaf.der, {}, "gateway.example.com");
    CHECK(!d.accept);
    CHECK(d.reason.find("expired") != std::string::npos);
}

TEST(cert, strict_rejects_untrusted_ca) {
    auto o = opts_with_bundle();
    OpenSslCertificateVerifier v(o);
    Decision d = evaluate_peer_cert(o, v, fx().rogue_leaf.der, {}, "gateway.example.com");
    CHECK(!d.accept);
    CHECK(d.reason.find("chain validation failed") != std::string::npos);
}

TEST(cert, strict_rejects_malformed_der) {
    auto o = opts_with_bundle();
    OpenSslCertificateVerifier v(o);
    std::vector<unsigned char> garbage{0x01, 0x02, 0x03, 0x04};
    Decision d = evaluate_peer_cert(o, v, garbage, {}, "gateway.example.com");
    CHECK(!d.accept);
    CHECK(d.reason.find("malformed") != std::string::npos);
}

TEST(cert, pinning_accepts_matching_fingerprint) {
    auto o = opts_with_bundle();
    OpenSslCertificateVerifier v(o);
    // Learn the fingerprint of the good leaf, then pin it.
    VerifyResult probe = v.verify(fx().good_leaf.der, {}, "gateway.example.com");
    CHECK(probe.ok);
    o.pinned_gateway_cert_sha256 = probe.leaf_sha256_hex;
    Decision d = evaluate_peer_cert(o, v, fx().good_leaf.der, {}, "gateway.example.com");
    CHECK(d.accept);
    CHECK(d.reason.find("pin matches") != std::string::npos);
}

TEST(cert, pinning_rejects_wrong_fingerprint) {
    auto o = opts_with_bundle();
    OpenSslCertificateVerifier v(o);
    // Chain is valid, but the pin does not match -> must still reject.
    o.pinned_gateway_cert_sha256 = std::string(64, '0');
    Decision d = evaluate_peer_cert(o, v, fx().good_leaf.der, {}, "gateway.example.com");
    CHECK(!d.accept);
    CHECK(d.reason.find("fingerprint mismatch") != std::string::npos);
}

TEST(cert, insecure_optin_accepts_expired_but_logs_it) {
    auto o = opts_with_bundle();
    o.allow_insecure_tls = true;  // explicit --ignore-tls-errors
    OpenSslCertificateVerifier v(o);
    Decision d = evaluate_peer_cert(o, v, fx().expired_leaf.der, {}, "gateway.example.com");
    CHECK(d.accept);
    CHECK(d.reason.find("INSECURE OPT-IN") != std::string::npos);
    CHECK(d.reason.find("expired") != std::string::npos);
}

TEST(cert, insecure_optin_with_valid_cert_is_noted) {
    auto o = opts_with_bundle();
    o.allow_insecure_tls = true;
    OpenSslCertificateVerifier v(o);
    Decision d = evaluate_peer_cert(o, v, fx().good_leaf.der, {}, "gateway.example.com");
    CHECK(d.accept);
    CHECK(d.reason.find("certificate valid") != std::string::npos);
}

TEST(cert, broken_bundle_fails_closed) {
    SecurityOptions o;
    o.ca_bundle_path = "/nonexistent/ca-bundle.pem";
    OpenSslCertificateVerifier v(o);
    Decision d = evaluate_peer_cert(o, v, fx().good_leaf.der, {}, "gateway.example.com");
    CHECK(!d.accept);
    CHECK(d.reason.find("trust store unavailable") != std::string::npos);
}

TEST(cert, normalize_pin_strips_separators_and_case) {
    CHECK_EQ(normalize_pin("AA:BB:CC"), std::string("aabbcc"));
    CHECK_EQ(normalize_pin("aa bb cc"), std::string("aabbcc"));
}

// ---------------------------------------------------------------------------
// CRL checking (Wave G, --check-crl): STRICTENING — chains without a valid
// CRL must be rejected, revoked certificates must be rejected.
// ---------------------------------------------------------------------------

namespace {
std::string make_crl_file(const certtest::TestCert& ca, const std::vector<long>& serials) {
    std::vector<unsigned char> der;
    REQUIRE(certtest::make_crl(ca, serials, &der));
    char tmpl[] = "/tmp/gp_crl_test_XXXXXX";
    int fd = mkstemp(tmpl);
    REQUIRE(fd >= 0);
    ::close(fd);
    std::string path = tmpl;
    certtest::write_crl_pem({der}, path);
    return path;
}
}  // namespace

TEST(cert, crl_check_rejects_revoked_certificate) {
    Fixture f;
    certtest::TestCert leaf;
    certtest::make_leaf(leaf, f.ca, "revoked.example.com", {"revoked.example.com"});
    std::string crl_path = make_crl_file(f.ca, {42});  // make_leaf serial is 42

    SecurityOptions opts;
    opts.check_crl = true;
    opts.ca_bundle_path = f.bundle_path;
    opts.crl_bundle_path = crl_path;
    OpenSslCertificateVerifier v(opts);
    Decision d = evaluate_peer_cert(opts, v, leaf.der, {}, "revoked.example.com");
    CHECK(!d.accept);
    CHECK(d.reason.find("revoked") != std::string::npos ||
          d.reason.find("CRL") != std::string::npos);
    ::unlink(crl_path.c_str());
}

TEST(cert, crl_check_accepts_unrevoked_certificate) {
    Fixture f;
    certtest::TestCert leaf;
    certtest::make_leaf(leaf, f.ca, "ok.example.com", {"ok.example.com"});
    std::string crl_path = make_crl_file(f.ca, {999});  // revokes nobody in our chain

    SecurityOptions opts;
    opts.check_crl = true;
    opts.ca_bundle_path = f.bundle_path;
    opts.crl_bundle_path = crl_path;
    OpenSslCertificateVerifier v(opts);
    Decision d = evaluate_peer_cert(opts, v, leaf.der, {}, "ok.example.com");
    CHECK(d.accept);
    ::unlink(crl_path.c_str());
}

TEST(cert, crl_check_without_available_crl_fails_closed) {
    Fixture f;
    certtest::TestCert leaf;
    certtest::make_leaf(leaf, f.ca, "nocrl.example.com", {"nocrl.example.com"});

    SecurityOptions opts;
    opts.check_crl = true;                // CRLs are now REQUIRED...
    opts.ca_bundle_path = f.bundle_path;  // ...but no CRL bundle is provided
    OpenSslCertificateVerifier v(opts);
    Decision d = evaluate_peer_cert(opts, v, leaf.der, {}, "nocrl.example.com");
    CHECK(!d.accept);
    CHECK(d.reason.find("CRL") != std::string::npos || d.reason.find("crl") != std::string::npos);
}

TEST(cert, crl_check_disabled_by_default_keeps_old_behavior) {
    Fixture f;
    certtest::TestCert leaf;
    certtest::make_leaf(leaf, f.ca, "default.example.com", {"default.example.com"});

    SecurityOptions opts;
    opts.ca_bundle_path = f.bundle_path;  // check_crl stays false
    OpenSslCertificateVerifier v(opts);
    Decision d = evaluate_peer_cert(opts, v, leaf.der, {}, "default.example.com");
    CHECK(d.accept);
}

int main() {
    return gp::test::Registry::instance().run_all();
}
