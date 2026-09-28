// GlobalProtect gateway API client (Wave F) — the browser-less auth flow that
// the GP portal performs for its own web client, driven over plain HTTP(S):
//
//   1. prelogin : GET /sslvpnd/prelogin.xml?server=<host>
//                 -> strict-XML <prelogin><session_id>...</session_id></prelogin>,
//                    plus the IKEY session cookie from Set-Cookie.
//   2. login    : GET /sslvpn-login (form discovery), then POST the form's
//                 hidden fields + username/password to its action. Redirects
//                 are followed MANUALLY so cookies set on intermediate hops
//                 are ingested before the next request.
//   3. connect  : GET /portal/index.html?server=<host>&IKEY=<session_id>,
//                 parse the returned form, POST its hidden fields to the
//                 action. The tunnel endpoint comes from the response's
//                 Location header (preferred) or a <form> action in the body.
//   4. extend   : re-POST the saved portal form to renew the session TTL.
//
// Security properties:
//  - Every HTTP request goes through gp::http::HttpClient, so mandatory
//    timeouts + response size caps (M-2) apply; TLS verification is on unless
//    --ignore-tls-errors.
//  - Cookies live in gp::cookies::Store (0700 dir / 0600 file enforced);
//    Set-Cookie values are parsed strictly and re-emitted only after the
//    control-character check, so a malicious gateway cannot inject headers.
//  - Redirect Locations must stay on the gateway origin: root-relative paths
//    or absolute URLs whose origin equals base_url. Anything else (foreign
//    host, protocol-relative "//host", other schemes) fails closed — session
//    cookies are never sent to third parties.
//  - prelogin.xml is parsed by the strict XML parser (DOCTYPE rejected => no
//    XXE); portal HTML is parsed by a minimal form extractor that rejects
//    NUL bytes, size overflow, and non-root-relative actions.
//  - Credentials appear ONLY in the login POST body; error strings never
//    contain username or password (H-3/M-3 redaction discipline).
//
// Scope: this client authenticates and obtains the tunnel endpoint. It does
// NOT implement the IPsec/DTLS data plane. The final-endpoint extraction
// accepts both shapes seen in the wild (redirect vs. form-in-body); validate
// against a real gateway before production use.
#pragma once

#include <cstddef>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "gp/cookie_store.h"
#include "gp/http_client.h"
#include "gp/security_options.h"

namespace gp::gateway {

// Minimal strict HTML form extractor for machine-generated portal pages.
struct HtmlForm {
    std::string action;  // root-relative path, validated (see parse_html_form)
    bool method_post = true;
    // Hidden inputs in document order. Non-hidden inputs are ignored: the
    // client only ever submits fields it can verify (no user input here).
    std::vector<std::pair<std::string, std::string>> fields;
};

// Parse the first <form> in `html` plus its hidden <input> elements.
// Fails closed on: NUL bytes, html.size() > max_bytes, no form tag, an action
// that is not a root-relative path (rejects absolute URLs, protocol-relative
// "//host/...", and any scheme such as javascript:/data:), or CR/LF/control
// characters in the action or in field names/values. Attribute values are
// entity-decoded (the five predefined references plus numeric refs).
bool parse_html_form(const std::string& html, size_t max_bytes, HtmlForm* out,
                     std::string* err = nullptr);

struct GatewayConfig {
    // Gateway hostname for ?server= query parameters ("gw.example.com").
    std::string gateway_host;
    // Origin used for requests: "https://gw.example.com" (no trailing slash).
    std::string base_url;
    int max_redirects = 5;
    // Extra fields appended to the portal connect POST. Escape hatch for
    // gateways whose form requires parameters beyond its hidden inputs.
    std::vector<std::pair<std::string, std::string>> connect_extra_fields;
};

class GatewayClient {
   public:
    // Opens (or creates) the cookie store at `cookie_dir`. Fails if the store
    // cannot be opened with enforced permissions.
    static std::unique_ptr<GatewayClient> create(const SecurityOptions& opts,
                                                 const GatewayConfig& cfg,
                                                 const std::string& cookie_dir,
                                                 std::string* err = nullptr);

    // Step 1. Requires HTTP 200 and a well-formed <prelogin> document with a
    // non-empty <session_id>. Ingests Set-Cookie (IKEY) from the response.
    bool prelogin(std::string* err = nullptr);

    // Step 2. Discovers the login form, then POSTs hidden fields + username +
    // password (+ IKEY when the form does not carry it). Follows redirects up
    // to max_redirects on the gateway origin, ingesting cookies each hop; the
    // final response must be 2xx. Error strings never contain credentials.
    bool login(const std::string& username, const std::string& password,
               std::string* err = nullptr);

    // Step 2b (IdP flows: SAML/CAS). Completes a browser-mediated login by
    // POSTing the captured callback payload as a single form field to
    // `return_path` (root-relative, e.g. "/sslvpn-login"), reusing the portal
    // session cookies established by prelogin(). Redirects are followed
    // manually with the same same-origin policy as login(); the final response
    // must be 2xx. Error strings never contain the payload (H-3/M-3).
    bool saml_login(const std::string& payload, const std::string& return_path,
                    const std::string& field_name, std::string* err = nullptr);

    // Step 3. Requires a prelogin() first. Performs the portal exchange and
    // stores the tunnel endpoint (see class comment for extraction rules).
    bool connect(std::string* err = nullptr);

    // Step 4. Re-POSTs the saved portal form; 2xx or 3xx counts as renewed.
    // Requires a successful connect() first.
    bool extend_session(std::string* err = nullptr);

    const std::string& session_id() const { return session_id_; }
    const std::string& tunnel_endpoint() const { return tunnel_endpoint_; }
    const cookies::Store& store() const { return store_; }

   private:
    GatewayClient(SecurityOptions opts, GatewayConfig cfg, cookies::Store store);

    // One request with the current cookie jar attached. `url` is absolute on
    // the gateway origin. On transport failure sets *err and returns a
    // response with ok == false.
    http::HttpResponse get(const std::string& path, std::string* err);
    http::HttpResponse post(const std::string& path,
                            const std::vector<std::pair<std::string, std::string>>& fields,
                            std::string* err);

    // Ingest every Set-Cookie of `res` into the store.
    void ingest_cookies(const http::HttpResponse& res);
    // Resolve a Location header value to an absolute URL on our origin.
    bool resolve_location(const std::string& location, std::string* out, std::string* err) const;

    SecurityOptions opts_;
    GatewayConfig cfg_;
    http::HttpClient http_;
    cookies::Store store_;
    std::string session_id_;
    std::string tunnel_endpoint_;
    // Saved portal form (action + fields) for extend_session().
    bool have_portal_form_ = false;
    std::string portal_action_;
    std::vector<std::pair<std::string, std::string>> portal_fields_;
};

}  // namespace gp::gateway