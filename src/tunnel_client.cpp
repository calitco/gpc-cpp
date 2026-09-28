// Tunnel layer implementation — see include/gp/tunnel_client.h for the design
// rationale (transport seam, C-1 wiring, safe port of patch 0005).
#include "gp/tunnel_client.h"

#include <cctype>
#include <utility>

#include "gp/trace.h"
#include "gp/xml.h"

namespace gp::tunnel {

namespace {

bool has_control_chars(const std::string& s) {
    for (unsigned char c : s)
        if (c < 0x20 || c == 0x7f)
            return true;
    return false;
}

// Split "scheme://host[:port][/path]" without pulling in a URL library.
// Returns false when the URL has no scheme or an empty host.
bool split_url(const std::string& url, std::string& scheme, std::string& host) {
    auto colon = url.find(':');
    if (colon == std::string::npos || colon + 4 > url.size())
        return false;
    scheme = url.substr(0, colon);
    for (auto& c : scheme)
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    if (url.compare(colon + 1, 2, "//") != 0)
        return false;
    size_t start = colon + 3;
    if (start >= url.size())
        return false;
    size_t end = url.find_first_of("/?#", start);
    host = (end == std::string::npos) ? url.substr(start) : url.substr(start, end - start);
    // Strip a trailing :port for the scheme/host rules.
    auto port_at = host.rfind(':');
    if (port_at != std::string::npos && host.find(':', port_at + 1) == std::string::npos)
        host.resize(port_at);
    return !host.empty();
}

}  // namespace

bool validate_tunnel_config(const TunnelConfig& cfg, std::string* err) {
    auto fail = [&](const std::string& msg) {
        if (err)
            *err = msg;
        return false;
    };
    if (cfg.endpoint_url.empty())
        return fail("tunnel endpoint URL is empty");
    if (has_control_chars(cfg.endpoint_url))
        return fail("tunnel endpoint URL contains control characters");

    std::string scheme, host;
    if (!split_url(cfg.endpoint_url, scheme, host))
        return fail("tunnel endpoint URL is malformed (expected scheme://host...)");
    if (cfg.endpoint_url.find('@') != std::string::npos)
        return fail("tunnel endpoint URL must not embed credentials");

    if (scheme == "https") {
        // ok
    } else if (scheme == "http" && host == "127.0.0.1") {
        // Loopback test servers only — never a real tunnel, never other hosts.
    } else {
        return fail(
            "tunnel endpoint must use https (http allowed only for "
            "127.0.0.1 loopback test servers)");
    }

    if (cfg.proto != "ipsec" && cfg.proto != "dtls")
        return fail("unsupported tunnel protocol '" + cfg.proto + "' (want ipsec or dtls)");
    return true;
}

bool parse_session_metadata(const std::string& doc, size_t max_bytes, SessionMetadata* out,
                            std::string* err) {
    auto fail = [&](const std::string& msg) {
        if (err)
            *err = msg;
        return false;
    };
    out->present = false;
    out->user.clear();
    out->user_expires.reset();

    // Empty document: the gateway simply did not report metadata.
    bool empty = true;
    for (unsigned char c : doc) {
        if (!std::isspace(c)) {
            empty = false;
            break;
        }
    }
    if (empty)
        return true;

    xml::Element root;
    std::string xerr;
    if (!xml::parse_xml(doc, max_bytes, &root, &xerr))
        return fail("metadata XML: " + xerr);

    const xml::Element* user = root.child("user");
    if (!user)
        return true;  // document without a <user> element: no metadata

    out->present = true;
    out->user = user->text_trim();

    // Safe port of the reference project's dual-attribute lookup (their patch
    // 0005): read the value only when at least one lookup succeeded. The XML
    // parser returns nullptr for absent attributes, so this cannot read an
    // uninitialized buffer — the audit's "verified non-issue", made explicit.
    const char* expires = user->attr("user-expires");
    if (!expires)
        expires = user->attr("user_expires");
    if (expires) {
        std::string v(expires);
        if (!v.empty())
            out->user_expires = std::move(v);
    }
    return true;
}

// ---------------------------------------------------------------------------
// CertPolicyCallback
// ---------------------------------------------------------------------------

CertPolicyCallback::CertPolicyCallback(SecurityOptions opts,
                                       std::unique_ptr<cert::CertificateVerifier> verifier)
    : opts_(std::move(opts)), verifier_(std::move(verifier)) {}

CertPolicyCallback::Result CertPolicyCallback::operator()(const PresentedCert& pc) const {
    Result r;
    cert::Decision d =
        cert::evaluate_peer_cert(opts_, *verifier_, pc.leaf_der, pc.intermediates, pc.host_or_ip);
    r.accept = d.accept;
    r.reason = d.reason.empty() ? (d.accept ? "accepted" : "rejected") : d.reason;
    return r;
}

// ---------------------------------------------------------------------------
// TunnelClient
// ---------------------------------------------------------------------------

TunnelClient::TunnelClient(SecurityOptions opts, std::unique_ptr<TunnelTransport> transport)
    : opts_(std::move(opts)),
      transport_(std::move(transport)),
      cert_cb_(std::make_unique<CertPolicyCallback>(
          opts_, std::make_unique<cert::OpenSslCertificateVerifier>(opts_))) {}

TunnelClient::~TunnelClient() {
    disconnect();
}

bool TunnelClient::connect(const TunnelConfig& cfg, const std::string& cookie_header,
                           std::string* err) {
    if (connected_) {
        if (err)
            *err = "tunnel: already connected";
        return false;
    }
    if (!transport_) {
        if (err)
            *err = "tunnel: no transport backend available";
        return false;
    }
    std::string verr;
    if (!validate_tunnel_config(cfg, &verr)) {
        if (err)
            *err = verr;
        return false;
    }
    GP_TRACE("tunnel: connecting to ", cfg.endpoint_url, " (proto=", cfg.proto, ")");

    decisions_.clear();
    metadata_ = SessionMetadata{};
    metadata_error_.clear();

    bool ok = transport_->connect(
        cfg, cookie_header,
        [this](const PresentedCert& pc) -> bool {
            auto r = (*cert_cb_)(pc);
            decisions_.emplace_back(r.accept, r.reason);
            GP_TRACE("tunnel: certificate ", r.accept ? "accepted" : "REJECTED", ": ",
                     r.reason);  // reason is log-safe by CertPolicyCallback contract
            return r.accept;
        },
        err);
    if (!ok) {
        // Append the certificate decision (if any) so the caller sees WHY.
        for (auto it = decisions_.rbegin(); it != decisions_.rend(); ++it) {
            if (!it->first && err && *err != it->second)
                *err += "; " + it->second;
            break;
        }
        return false;
    }

    std::string meta_doc = transport_->session_metadata_xml();
    if (!meta_doc.empty()) {
        std::string merr;
        if (!parse_session_metadata(meta_doc, 1u << 20, &metadata_, &merr))
            metadata_error_ = merr;  // informational: surfaced, not fatal
    }

    connected_ = true;
    if (metadata_.present) {
        GP_TRACE("tunnel: session user '", metadata_.user, "'");
        if (metadata_.user_expires.has_value())
            GP_TRACE("tunnel: session expires ", *metadata_.user_expires);
    } else {
        GP_TRACE("tunnel: connected (no session metadata reported)");
    }
    return true;
}

void TunnelClient::disconnect() {
    // Idempotent: the transport sees at most one disconnect per connect.
    if (!connected_)
        return;
    if (transport_)
        transport_->disconnect();
    connected_ = false;
    GP_TRACE("tunnel: disconnected");
}

const SessionMetadata* TunnelClient::metadata() const {
    return &metadata_;
}

const std::vector<std::pair<bool, std::string>>& TunnelClient::cert_decisions() const {
    return decisions_;
}

}  // namespace gp::tunnel