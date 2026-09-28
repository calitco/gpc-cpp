#include "gp/cert_policy.h"

#include <arpa/inet.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <cstring>
#include <fstream>

namespace gp::cert {

std::string normalize_pin(const std::string& pin) {
    std::string out;
    for (char c : pin) {
        if (c == ':' || c == ' ' || c == '\t')
            continue;
        out += static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }
    return out;
}

// ---------------------------------------------------------------------------
// OpenSSL backend
// ---------------------------------------------------------------------------

struct OpenSslCertificateVerifier::Impl {
    X509_STORE* store = nullptr;
    bool broken = false;
    std::string broken_reason;

    ~Impl() {
        if (store)
            X509_STORE_free(store);
    }
};

OpenSslCertificateVerifier::OpenSslCertificateVerifier(const SecurityOptions& opts)
    : impl_(std::make_unique<Impl>()) {
    impl_->store = X509_STORE_new();
    if (!impl_->store) {
        impl_->broken = true;
        impl_->broken_reason = "cannot allocate X509_STORE";
        return;
    }
    if (opts.ca_bundle_path.has_value()) {
        // Operator-specified bundle: use ONLY it (explicit intent), fail closed
        // if it cannot be read.
        X509_LOOKUP* lk = X509_STORE_add_lookup(impl_->store, X509_LOOKUP_file());
        if (!lk ||
            X509_LOOKUP_load_file(lk, opts.ca_bundle_path->c_str(), X509_FILETYPE_PEM) != 1) {
            impl_->broken = true;
            impl_->broken_reason = "cannot load CA bundle: " + *opts.ca_bundle_path;
            return;
        }
    } else {
        if (X509_STORE_set_default_paths(impl_->store) != 1) {
            impl_->broken = true;
            impl_->broken_reason = "cannot load system trust store";
            return;
        }
    }
    if (opts.check_crl) {
        // STRICTENING: require a valid CRL for every non-root certificate in the
        // chain. If no CRL is available, X509_verify_cert() fails with
        // "CRL has expired" / "CRL missing" — fail closed by construction.
        if (opts.crl_bundle_path.has_value()) {
            X509_LOOKUP* lk = X509_STORE_add_lookup(impl_->store, X509_LOOKUP_file());
            if (!lk ||
                X509_LOOKUP_load_file(lk, opts.crl_bundle_path->c_str(), X509_FILETYPE_PEM) != 1) {
                impl_->broken = true;
                impl_->broken_reason = "cannot load CRL bundle: " + *opts.crl_bundle_path;
                return;
            }
        }
        if (X509_STORE_set_flags(impl_->store, X509_V_FLAG_CRL_CHECK) != 1) {
            impl_->broken = true;
            impl_->broken_reason = "cannot enable CRL checking";
            return;
        }
    }
}

OpenSslCertificateVerifier::~OpenSslCertificateVerifier() = default;

namespace {
std::string sha256_hex(const unsigned char* data, std::size_t len) {
    unsigned char digest[32];
    SHA256(data, len, digest);
    static const char* h = "0123456789abcdef";
    std::string out(64, '0');
    for (int i = 0; i < 32; ++i) {
        out[2 * i] = h[digest[i] >> 4];
        out[2 * i + 1] = h[digest[i] & 0xf];
    }
    return out;
}

X509* parse_der(const std::vector<unsigned char>& der) {
    const unsigned char* p = der.data();
    return d2i_X509(nullptr, &p, static_cast<long>(der.size()));
}

bool is_ip_literal(const std::string& s, int& family) {
    struct in_addr a4;
    if (inet_pton(AF_INET, s.c_str(), &a4) == 1) {
        family = AF_INET;
        return true;
    }
    struct in6_addr a6;
    if (inet_pton(AF_INET6, s.c_str(), &a6) == 1) {
        family = AF_INET6;
        return true;
    }
    family = 0;
    return false;
}
}  // namespace

VerifyResult OpenSslCertificateVerifier::verify(
    const std::vector<unsigned char>& leaf,
    const std::vector<std::vector<unsigned char>>& untrusted_intermediates,
    const std::string& host_or_ip) {
    VerifyResult res;
    if (impl_->broken) {
        res.reason = "trust store unavailable: " + impl_->broken_reason;
        return res;
    }

    X509* x = parse_der(leaf);
    if (!x) {
        res.reason = "malformed DER certificate from server";
        return res;
    }

    // Fingerprint over the exact DER bytes presented (same input as
    // `openssl x509 -fingerprint -sha256`).
    unsigned char* der = nullptr;
    int der_len = i2d_X509(x, &der);
    if (der_len > 0 && der) {
        res.leaf_sha256_hex = sha256_hex(der, static_cast<std::size_t>(der_len));
        OPENSSL_free(der);
    }

    STACK_OF(X509)* untrusted = sk_X509_new_null();
    for (const auto& inter : untrusted_intermediates) {
        X509* ix = parse_der(inter);
        if (ix)
            sk_X509_push(untrusted, ix);
        else {
            X509_free(x);
            sk_X509_pop_free(untrusted, X509_free);
            res.reason = "malformed intermediate certificate";
            return res;
        }
    }

    X509_STORE_CTX* ctx = X509_STORE_CTX_new();
    bool ok = false;
    if (ctx && X509_STORE_CTX_init(ctx, impl_->store, x, untrusted) == 1) {
        if (X509_verify_cert(ctx) == 1) {
            int family = 0;
            if (is_ip_literal(host_or_ip, family)) {
                unsigned char ipbuf[16] = {0};
                if (family == AF_INET) {
                    struct in_addr a;
                    inet_pton(AF_INET, host_or_ip.c_str(), &a);
                    std::memcpy(ipbuf, &a, 4);
                    ok = X509_check_ip(x, ipbuf, 4, 0) == 1;
                } else {
                    struct in6_addr a;
                    inet_pton(AF_INET6, host_or_ip.c_str(), &a);
                    std::memcpy(ipbuf, &a, 16);
                    ok = X509_check_ip(x, ipbuf, 16, 0) == 1;
                }
                if (!ok)
                    res.reason = "certificate does not cover IP " + host_or_ip;
            } else {
                ok = X509_check_host(x, host_or_ip.c_str(), 0, 0, nullptr) == 1;
                if (!ok)
                    res.reason = "hostname mismatch for '" + host_or_ip + "'";
            }
        } else {
            int err = X509_STORE_CTX_get_error(ctx);
            res.reason =
                std::string("chain validation failed: ") + X509_verify_cert_error_string(err);
        }
    } else {
        res.reason = "internal error initializing certificate verification";
    }

    if (ctx)
        X509_STORE_CTX_free(ctx);
    sk_X509_pop_free(untrusted, X509_free);
    X509_free(x);

    res.ok = ok;
    if (ok)
        res.reason = "certificate verified";
    return res;
}

// ---------------------------------------------------------------------------
// Policy decision
// ---------------------------------------------------------------------------

Decision evaluate_peer_cert(const SecurityOptions& opts, CertificateVerifier& verifier,
                            const std::vector<unsigned char>& leaf,
                            const std::vector<std::vector<unsigned char>>& untrusted_intermediates,
                            const std::string& host_or_ip) {
    Decision d;

    VerifyResult v = verifier.verify(leaf, untrusted_intermediates, host_or_ip);

    if (opts.allow_insecure_tls) {
        // Explicit opt-in (--ignore-tls-errors). Still record WHY validation
        // failed so the weakening is auditable in logs.
        d.accept = true;
        d.reason = v.ok ? "insecure mode: certificate valid (opt-in --ignore-tls-errors)"
                        : "INSECURE OPT-IN: accepting unvalidated certificate (" + v.reason +
                              ") via --ignore-tls-errors";
        return d;
    }

    if (!v.ok) {
        d.accept = false;
        d.reason = "rejected: " + v.reason;
        return d;
    }

    if (opts.pinned_gateway_cert_sha256.has_value()) {
        const std::string want = normalize_pin(*opts.pinned_gateway_cert_sha256);
        const std::string got = normalize_pin(v.leaf_sha256_hex);
        if (want != got) {
            d.accept = false;
            d.reason = "rejected: certificate fingerprint mismatch (pinning enabled)";
            return d;
        }
        d.accept = true;
        d.reason = "accepted: chain valid and fingerprint pin matches";
        return d;
    }

    d.accept = true;
    d.reason = "accepted: chain and hostname verified";
    return d;
}

}  // namespace gp::cert
