// Cookie persistence — port of the Rust `cookie_store.rs` behavior (0700
// dirs, 0600 files, which the audit verified as good), hardened with the
// same post-write mode verification and atomic writes used by gp::secrets.
//
// Format: Netscape cookies.txt (tab-separated), one cookie per line:
//   domain \t include_subdomains(0/1) \t path \t secure(0/1) \t expiration \t name \t value
// Malformed lines in an existing file are skipped (and counted), never fatal.
#pragma once

#include <chrono>
#include <cstddef>
#include <optional>
#include <string>
#include <vector>

namespace gp::cookies {

inline std::chrono::system_clock::time_point epoch() {
    return std::chrono::system_clock::from_time_t(0);
}

struct Cookie {
    std::string name;
    std::string value;
    std::string domain;  // host that set it (leading dot normalized away)
    std::string path = "/";
    // nullopt means a session cookie (no explicit expiry). Any explicit value
    // <= now is expired.
    std::optional<std::chrono::system_clock::time_point> expires;
    bool secure = false;
    bool http_only = false;
    // True when the server did not send an explicit Domain attribute and we
    // derived the domain from the request host: such cookies must NOT be sent
    // to sibling subdomains (RFC 6265 host-only rule).
    bool host_only = true;
};

// Parse a Set-Cookie header value (RFC 6265 section 4.1.1). `default_domain`
// is used when no Domain attribute is present; such cookies stay host-only.
// Returns nullopt when the cookie-pair name or value is empty, contains
// control characters / tabs (header-injection defense for re-emitted Cookie
// headers), or the pair is malformed. Attributes recognized: Domain, Path,
// Expires, Max-Age (overrides Expires; <= 0 means already expired), Secure,
// HttpOnly. Unparseable Expires/Path values are ignored per spec.
std::optional<Cookie> parse_set_cookie(const std::string& header_value,
                                       const std::string& default_domain);

class Store {
   public:
    // Open (or create) the store at `dir`. The directory is forced to 0700 and
    // cookies.txt to 0600 regardless of umask; if enforcement fails (e.g. not
    // the owner) the call fails closed. On success ok() is true; a malformed
    // existing file yields a store with only its valid lines plus skipped_().
    static Store open(const std::string& dir, std::string* err = nullptr);
    bool ok() const { return ok_; }
    size_t skipped_lines() const { return skipped_; }

    // Upsert by (domain, path, name). Returns false (and persists nothing) if
    // name/value contain characters that cannot be represented in the file
    // format (tabs, newlines) or if the on-disk write fails.
    bool set(const Cookie& c, std::string* err = nullptr);

    // Exact (domain, path, name) lookup.
    std::optional<Cookie> find(const std::string& domain, const std::string& path,
                               const std::string& name) const;

    // Cookies to send to `host` (request `path`) over `https`: domain-match
    // (host == domain, or subdomain when the cookie is not host-only), RFC 6265
    // path prefix match, secure cookies only on https, expired cookies pruned.
    // Ordered by path length (longest first) then name, for determinism.
    std::vector<Cookie> for_request(const std::string& host, bool https,
                                    const std::string& path = "/") const;

    // Remove all entries with (domain, name). Returns true if anything removed.
    bool remove(const std::string& domain, const std::string& name);

    size_t size() const { return cookies_.size(); }
    const std::string& dir_path() const { return dir_; }

   private:
    Store() = default;
    bool load(std::string* err);
    // Atomic write: temp file in the same dir, 0600 verified, fsync, rename.
    bool save(std::string* err) const;

    std::string dir_;
    std::vector<Cookie> cookies_;
    size_t skipped_ = 0;
    bool ok_ = false;
};

}  // namespace gp::cookies