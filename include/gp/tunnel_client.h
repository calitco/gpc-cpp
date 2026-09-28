// Tunnel layer (Wave G) — the security-relevant surface of the GlobalProtect
// tunnel data plane, decoupled from the actual OpenConnect backend.
//
// Why a transport interface? Upstream libopenconnect does not speak
// GlobalProtect; the reference project runs it with private patches (their
// 0005-Expose-GlobalProtect-session-metadata.patch). This module therefore
// implements and unit-tests everything that is security-relevant INDEPENDENT
// of the backend:
//
//  - endpoint URL validation (scheme rules, no embedded credentials);
//  - CertPolicyCallback: the tunnel-level fix for finding C-1. A backend MUST
//    route every presented certificate through this callback (the exact
//    function a fixed OpenConnect validate_peer_cert() would call). The old
//    shim returned "accept" unconditionally; here the full SecurityOptions
//    policy applies — strict by default, pinning, audited opt-in — and every
//    decision is recorded for logging. A backend that cannot enforce this is
//    simply not built in, never silently weakened.
//  - SessionMetadata: a safe C++ port of the reference project's patch 0005
//    (user / user-expires extraction). The audit flagged an apparent
//    uninitialized-read there ("verified non-issue"); this port keeps that
//    property explicit: the expires field is only read when at least one of
//    the two attribute lookups succeeded, and everything else goes through
//    the strict XML parser (DOCTYPE rejected => no XXE).
//  - CRL checking (gp::cert with --check-crl) applies to tunnel TLS via the
//    same verifier the callback uses.
//
// The production backend wraps (patched) libopenconnect and implements
// TunnelTransport; it is an integration seam, compiled in only when the
// library is available. Tests inject FakeTransport-style fakes, so the whole
// policy layer is exercised without any tunnel dependency.
#pragma once

#include <cstddef>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "gp/cert_policy.h"
#include "gp/security_options.h"

namespace gp::tunnel {

struct TunnelConfig {
    // The endpoint obtained from GatewayClient::tunnel_endpoint(), e.g.
    // "https://gw.example.com/tunnel/start?proto=ipsec&key=...". https is
    // required; http://127.0.0.1 is accepted for loopback test servers only.
    std::string endpoint_url;
    // Tunnel protocol: "ipsec" or "dtls".
    std::string proto = "ipsec";
};

// Validate a tunnel endpoint URL. Rules (all fail closed):
//  - non-empty, no control characters;
//  - scheme must be https, or http with host exactly 127.0.0.1 (loopback);
//  - no embedded credentials (userinfo "@");
//  - proto must be "ipsec" or "dtls".
bool validate_tunnel_config(const TunnelConfig& cfg, std::string* err = nullptr);

// Session metadata reported by the gateway after tunnel establishment
// (port of the reference project's OpenConnect patch 0005, made safe).
struct SessionMetadata {
    bool present = false;
    std::string user;
    // Raw expiry string exactly as the gateway reports it (the format is
    // gateway-defined); nullopt when the document carried neither of the two
    // known attribute names.
    std::optional<std::string> user_expires;
};

// Parse a session-metadata XML document. Accepts an empty document (no
// metadata => present=false, success). Non-empty documents are parsed by the
// strict XML parser: DOCTYPE rejected, size-capped, depth-capped. The root
// element name is not mandated (gateways vary); the <user> child and the
// user-expires / user_expires attributes on it are recognized.
bool parse_session_metadata(const std::string& doc, size_t max_bytes, SessionMetadata* out,
                            std::string* err = nullptr);

// A certificate presented by the tunnel backend during its handshake.
struct PresentedCert {
    std::vector<unsigned char> leaf_der;
    std::vector<std::vector<unsigned char>> intermediates;
    std::string host_or_ip;  // the endpoint host (or IP) being connected to
};

// The certificate decision point (C-1 at tunnel level). Applies the full
// SecurityOptions policy via gp::cert::evaluate_peer_cert and returns a
// log-safe reason. The callback OWNS its verifier; production code passes an
// OpenSslCertificateVerifier, tests may pass any CertificateVerifier.
class CertPolicyCallback {
   public:
    struct Result {
        bool accept = false;
        std::string reason;  // always non-empty, safe to log (no secrets)
    };

    CertPolicyCallback(SecurityOptions opts, std::unique_ptr<cert::CertificateVerifier> verifier);
    Result operator()(const PresentedCert& pc) const;

   private:
    SecurityOptions opts_;
    std::unique_ptr<cert::CertificateVerifier> verifier_;
};

// Backend interface for the actual tunnel data plane. Implementations MUST:
//  - call on_cert for every certificate presented and ABORT the connection
//    when it returns false (no blanket accept — C-1);
//  - never log credentials or cookie values;
//  - be safe to destroy while connected (destructor disconnects).
class TunnelTransport {
   public:
    using CertCallback = std::function<bool(const PresentedCert&)>;

    virtual ~TunnelTransport() = default;
    // Establish the tunnel to cfg.endpoint_url, sending `cookie_header` as the
    // session Cookie header. Returns false (with *err) on any failure,
    // including a rejected certificate.
    virtual bool connect(const TunnelConfig& cfg, const std::string& cookie_header,
                         CertCallback on_cert, std::string* err = nullptr) = 0;
    virtual void disconnect() = 0;
    virtual bool connected() const = 0;
    // Raw session-metadata document as reported by the gateway (may be empty).
    virtual std::string session_metadata_xml() const = 0;
};

// Orchestrates: config validation -> transport connect with the certificate
// policy wired in -> metadata parse. RAII disconnect on destruction; no
// static state, so any number of concurrent clients are safe (the old C shim
// kept global state — see findings doc).
class TunnelClient {
   public:
    // `transport` must be non-null. The certificate verifier is constructed
    // from `opts` (OpenSslCertificateVerifier) and owned by this client.
    TunnelClient(SecurityOptions opts, std::unique_ptr<TunnelTransport> transport);
    ~TunnelClient();  // disconnects if still connected
    TunnelClient(const TunnelClient&) = delete;
    TunnelClient& operator=(const TunnelClient&) = delete;

    bool connect(const TunnelConfig& cfg, const std::string& cookie_header,
                 std::string* err = nullptr);
    void disconnect();  // idempotent
    bool connected() const { return connected_; }

    // Valid after a successful connect(). present==false when the gateway sent
    // no (or an empty) metadata document.
    const SessionMetadata* metadata() const;
    // Set when a non-empty metadata document failed to parse (connect still
    // succeeds: metadata is informational, but the failure is surfaced).
    const std::string& metadata_error() const { return metadata_error_; }

    // Audit trail of every certificate decision in order: (accepted, reason).
    const std::vector<std::pair<bool, std::string>>& cert_decisions() const;

   private:
    SecurityOptions opts_;
    std::unique_ptr<TunnelTransport> transport_;
    std::unique_ptr<CertPolicyCallback> cert_cb_;
    SessionMetadata metadata_{};
    std::string metadata_error_;
    bool connected_ = false;
    std::vector<std::pair<bool, std::string>> decisions_;
};

}  // namespace gp::tunnel