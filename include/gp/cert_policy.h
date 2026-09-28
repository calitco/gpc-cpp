// Certificate validation policy — the C++ replacement for the old C shim's
// validate_peer_cert() which unconditionally returned 0 (finding C-1).
//
// The decision function here is what a fixed OpenConnect callback must call:
//   - default (Strict): full chain validation + hostname/IP check; ANY failure
//     rejects the connection. There is no blanket accept.
//   - Pinned: strict validation PLUS SHA-256 fingerprint pin of the leaf.
//   - Insecure: only when SecurityOptions::allow_insecure_tls was explicitly
//     set on the command line (--ignore-tls-errors). The decision is still
//     logged with the exact failure reason, so opt-in misuse is auditable.
#pragma once

#include <cstddef>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "gp/security_options.h"

namespace gp::cert {

struct VerifyResult {
    bool ok = false;
    std::string reason;           // human-readable, safe to log (no secrets)
    std::string leaf_sha256_hex;  // fingerprint of the presented leaf
};

// Abstract so unit tests can inject fake verifiers without OpenSSL.
class CertificateVerifier {
   public:
    virtual ~CertificateVerifier() = default;
    // Verify `leaf` (DER) against the trust store, optionally using
    // `untrusted_intermediates` (DER list), and check hostname or IP.
    virtual VerifyResult verify(
        const std::vector<unsigned char>& leaf,
        const std::vector<std::vector<unsigned char>>& untrusted_intermediates,
        const std::string& host_or_ip) = 0;
};

// OpenSSL-backed implementation: X509 chain validation (system default paths,
// or the CA bundle from options.ca_bundle_path when set) + X509_check_host /
// X509_check_ip. Construction failure (e.g. unreadable CA bundle) is reported
// via ok=false on every verify call — fail closed, never fall back to accept.
class OpenSslCertificateVerifier : public CertificateVerifier {
   public:
    explicit OpenSslCertificateVerifier(const SecurityOptions& opts);
    ~OpenSslCertificateVerifier() override;

    VerifyResult verify(const std::vector<unsigned char>& leaf,
                        const std::vector<std::vector<unsigned char>>& untrusted_intermediates,
                        const std::string& host_or_ip) override;

   private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

struct Decision {
    bool accept = false;
    std::string reason;  // always non-empty; suitable for logging
};

// The policy decision. `opts` carries the operator's switches; `verifier`
// performs the actual cryptographic checks.
Decision evaluate_peer_cert(const SecurityOptions& opts, CertificateVerifier& verifier,
                            const std::vector<unsigned char>& leaf,
                            const std::vector<std::vector<unsigned char>>& untrusted_intermediates,
                            const std::string& host_or_ip);

// Normalize a pin (strip ':' / whitespace, lowercase) for comparison.
std::string normalize_pin(const std::string& pin);

}  // namespace gp::cert
