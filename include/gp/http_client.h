// HTTP client with mandatory timeouts and response size caps — fixes finding
// M-2 (the Rust reqwest clients had no .timeout()/.connect_timeout() and no
// body cap, so a malicious portal could hang or OOM the client).
//
// TLS verification is always on unless the explicit --ignore-tls-errors
// switch was given (same opt-in model as the tunnel policy in cert_policy.h).
#pragma once

#include <cstddef>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "gp/security_options.h"

namespace gp::http {

struct HttpResponse {
    bool ok = false;       // transport + size-cap success (not HTTP status)
    long status_code = 0;  // HTTP status of the final response, 0 if none
    std::string body;      // body of the final response
    std::string error;     // human-readable failure reason (safe to log)
    // Headers of the FINAL response. Names are lowercased and trimmed, values
    // trimmed. Duplicate names are appended (look up from the end if needed).
    std::vector<std::pair<std::string, std::string>> headers;
    // Values of every Set-Cookie header seen on ANY redirect hop: gateways set
    // session cookies on intermediate 3xx responses, not just the final one.
    std::vector<std::string> set_cookie_headers;
};

struct RequestOptions {
    // When false, the first response is returned as-is (e.g. a 3xx) and the
    // caller resolves Location itself. Needed for stateful cookie flows where
    // each hop must ingest cookies before deciding where to go next.
    bool follow_redirects = true;
    // Extra request headers sent verbatim (e.g. "Cookie: ..."). Values must not
    // contain CR/LF — the caller is responsible for that validation.
    std::vector<std::pair<std::string, std::string>> headers;
};

class HttpClient {
   public:
    explicit HttpClient(const SecurityOptions& opts);
    ~HttpClient();

    HttpResponse get(const std::string& url, const RequestOptions& opts = {});
    HttpResponse post(const std::string& url, const std::string& body,
                      const std::string& content_type = "application/x-www-form-urlencoded",
                      const RequestOptions& opts = {});

   private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace gp::http
