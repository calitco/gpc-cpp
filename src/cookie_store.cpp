// Cookie persistence implementation. See include/gp/cookie_store.h for the
// security properties (0700 dir / 0600 file enforced and re-verified, atomic
// writes, fail-closed on any permission mismatch).
#include "gp/cookie_store.h"

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <ctime>
#include <sstream>

namespace gp::cookies {

namespace {

std::string normalize_domain(std::string d) {
    while (!d.empty() && d.front() == '.')
        d.erase(d.begin());
    return d;
}

bool line_is_bad(const std::string& s) {
    return s.find('\t') != std::string::npos || s.find('\n') != std::string::npos ||
           s.find('\r') != std::string::npos;
}

// RFC 6265 section 5.1.4 path-match.
bool path_matches(const std::string& cookie_path, const std::string& req_path) {
    if (cookie_path == req_path)
        return true;
    if (req_path.rfind(cookie_path, 0) != 0)
        return false;
    if (cookie_path.empty() || cookie_path.back() == '/')
        return true;
    return req_path.size() > cookie_path.size() && req_path[cookie_path.size()] == '/';
}

bool domain_matches(const Cookie& c, const std::string& host) {
    if (host == c.domain)
        return true;
    if (c.host_only)
        return false;
    const std::string suffix = "." + c.domain;
    return host.size() > suffix.size() &&
           host.compare(host.size() - suffix.size(), suffix.size(), suffix) == 0;
}

bool parse_line(const std::string& raw, Cookie* out, bool* ok) {
    std::string line = raw;
    if (!line.empty() && line.back() == '\r')
        line.pop_back();
    if (line.empty() || line[0] == '#') {
        *ok = true;  // comments/blank: valid, nothing to store
        return false;
    }
    std::vector<std::string> f;
    std::string cur;
    for (char ch : line) {
        if (ch == '\t') {
            f.push_back(cur);
            cur.clear();
        } else {
            cur.push_back(ch);
        }
    }
    f.push_back(cur);
    if (f.size() != 7)
        return false;

    Cookie c;
    c.domain = normalize_domain(f[0]);
    c.host_only = f[1] != "1";
    c.path = f[2].empty() ? "/" : f[2];
    c.secure = f[3] == "1";
    char* end = nullptr;
    long exp = std::strtol(f[4].c_str(), &end, 10);
    if (end == f[4].c_str() || *end != '\0')
        return false;
    c.expires = exp <= 0 ? std::nullopt
                         : std::optional<std::chrono::system_clock::time_point>(
                               std::chrono::system_clock::from_time_t(static_cast<time_t>(exp)));
    c.name = f[5];
    c.value = f[6];
    if (c.domain.empty() || c.name.empty())
        return false;

    *out = std::move(c);
    *ok = true;
    return true;
}

// ---- Set-Cookie parsing helpers (RFC 6265 section 4.1.1) ------------------

std::string trim_ws(const std::string& s) {
    // Strip all ASCII line whitespace too: a Set-Cookie value arriving with a
    // trailing CRLF (e.g. from a header parser that keeps line terminators)
    // must not leak into the last attribute's value.
    size_t f = s.find_first_not_of(" \t\r\n");
    if (f == std::string::npos)
        return "";
    size_t l = s.find_last_not_of(" \t\r\n");
    return s.substr(f, l - f + 1);
}

std::string to_lower(std::string s) {
    for (auto& c : s)
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}

// cookie-name is *token: printable ASCII without space or delimiters.
bool valid_cookie_name(const std::string& s) {
    if (s.empty())
        return false;
    for (unsigned char c : s) {
        if (c < 0x21 || c > 0x7e)
            return false;
        if (std::strchr("()\"/,:<>?@[]\\{}", static_cast<int>(c)))
            return false;
    }
    return true;
}

// Values may be quoted or bare; control chars / DEL are always rejected so a
// malicious Set-Cookie cannot inject headers when the cookie is re-emitted.
bool valid_cookie_value(const std::string& s) {
    for (unsigned char c : s) {
        if (c < 0x20 || c == 0x7f)
            return false;
    }
    return true;
}

// HTTP-date: IMF-fixdate ("Sun, 06 Nov 1994 08:49:37 GMT") or the obsolete
// asctime form ("Sun Nov  6 08:49:37 1994"). Both are UTC. nullopt = unparseable.
std::optional<std::chrono::system_clock::time_point> parse_http_date(const std::string& s) {
    struct tm t{};
    if (!strptime(s.c_str(), "%a, %d %b %Y %H:%M:%S", &t) &&
        !strptime(s.c_str(), "%a %b %d %H:%M:%S %Y", &t)) {
        return std::nullopt;
    }
    t.tm_isdst = 0;
    time_t utc = timegm(&t);
    if (utc < 0)
        return std::nullopt;
    return std::chrono::system_clock::from_time_t(utc);
}

}  // namespace

std::optional<Cookie> parse_set_cookie(const std::string& header_value,
                                       const std::string& default_domain) {
    std::string v = trim_ws(header_value);
    if (v.empty())
        return std::nullopt;

    // Cookie-pair is everything before the first ';'.
    auto sc = v.find(';');
    std::string pair = (sc == std::string::npos) ? v : v.substr(0, sc);
    auto eq = pair.find('=');
    if (eq == std::string::npos)
        return std::nullopt;

    std::string name = trim_ws(pair.substr(0, eq));
    std::string value = trim_ws(pair.substr(eq + 1));
    if (value.size() >= 2 && value.front() == '"' && value.back() == '"') {
        value = value.substr(1, value.size() - 2);
        if (value.find('"') != std::string::npos)
            return std::nullopt;
    }
    if (!valid_cookie_name(name) || !valid_cookie_value(value))
        return std::nullopt;

    Cookie c;
    c.name = name;
    c.value = value;
    c.domain = normalize_domain(default_domain);
    c.host_only = true;  // no Domain attribute => host-only (RFC 6265 5.2.3)
    c.path = "/";

    size_t pos = (sc == std::string::npos) ? v.size() : sc + 1;
    while (pos < v.size()) {
        auto next = v.find(';', pos);
        std::string attr =
            trim_ws(v.substr(pos, (next == std::string::npos) ? v.size() : next - pos));
        pos = (next == std::string::npos) ? v.size() : next + 1;
        if (attr.empty())
            continue;

        auto aeq = attr.find('=');
        std::string aname =
            to_lower(trim_ws(aeq == std::string::npos ? attr : attr.substr(0, aeq)));
        std::string aval = (aeq == std::string::npos) ? "" : trim_ws(attr.substr(aeq + 1));

        if (aname == "domain") {
            std::string d = normalize_domain(to_lower(aval));
            if (!d.empty()) {
                c.domain = d;
                c.host_only = false;
            }
        } else if (aname == "path") {
            // Malformed paths (not starting with '/') are ignored per spec.
            if (!aval.empty() && aval.front() == '/')
                c.path = aval;
        } else if (aname == "expires") {
            auto t = parse_http_date(aval);
            if (t)
                c.expires = *t;  // unparseable => attribute ignored
        } else if (aname == "max-age") {
            char* endp = nullptr;
            long secs = std::strtol(aval.c_str(), &endp, 10);
            if (endp != aval.c_str() && *endp == '\0') {
                // Max-Age overrides Expires. <= 0 => already expired (epoch).
                c.expires = std::chrono::system_clock::from_time_t(
                    secs <= 0 ? 0 : static_cast<time_t>(time(nullptr) + secs));
            }
        } else if (aname == "secure") {
            c.secure = true;
        } else if (aname == "httponly") {
            c.http_only = true;
        }
        // Unknown attributes are ignored.
    }

    if (c.domain.empty())
        return std::nullopt;
    return c;
}

Store Store::open(const std::string& dir, std::string* err) {
    Store s;
    s.dir_ = dir;

    if (mkdir(dir.c_str(), 0700) != 0 && errno != EEXIST) {
        if (err)
            *err = "mkdir failed: " + std::string(std::strerror(errno));
        return s;
    }
    int dfd = ::open(dir.c_str(), O_RDONLY | O_DIRECTORY);
    if (dfd < 0) {
        if (err)
            *err = "open dir failed: " + std::string(std::strerror(errno));
        return s;
    }
    // Enforce 0700 regardless of umask and verify.
    if (fchmod(dfd, 0700) != 0) {
        if (err)
            *err = "cannot enforce 0700 on store dir: " + std::string(std::strerror(errno));
        ::close(dfd);
        return s;
    }
    struct stat st{};
    if (fstat(dfd, &st) != 0 || (st.st_mode & 0777) != 0700) {
        if (err)
            *err = "store dir mode is not 0700 after fchmod";
        ::close(dfd);
        return s;
    }
    ::close(dfd);

    const std::string fpath = dir + "/cookies.txt";
    int fd = ::open(fpath.c_str(), O_RDWR | O_CREAT, 0600);
    if (fd < 0) {
        if (err)
            *err = "open cookies.txt failed: " + std::string(std::strerror(errno));
        return s;
    }
    if (fchmod(fd, 0600) != 0 || fstat(fd, &st) != 0 || (st.st_mode & 0777) != 0600) {
        if (err)
            *err = "cannot enforce/verify 0600 on cookies.txt";
        ::close(fd);
        return s;
    }

    // Read the whole file from the fd we already hold.
    std::string content;
    if (st.st_size > 0) {
        content.resize(static_cast<size_t>(st.st_size));
        size_t got = 0;
        while (got < content.size()) {
            ssize_t n = ::read(fd, content.data() + got, content.size() - got);
            if (n < 0) {
                if (errno == EINTR)
                    continue;
                if (err)
                    *err = "read cookies.txt failed: " + std::string(std::strerror(errno));
                ::close(fd);
                return s;
            }
            if (n == 0)
                break;
            got += static_cast<size_t>(n);
        }
        content.resize(got);
    }
    ::close(fd);

    std::istringstream in(content);
    std::string line;
    while (std::getline(in, line)) {
        Cookie c;
        bool ok = false;
        if (parse_line(line, &c, &ok)) {
            s.cookies_.push_back(std::move(c));
        } else if (!ok) {
            ++s.skipped_;  // malformed: skipped, never fatal
        }
    }

    s.ok_ = true;
    return s;
}
bool Store::set(const Cookie& c, std::string* err) {
    if (!ok_) {
        if (err)
            *err = "store not open";
        return false;
    }
    if (c.name.empty() || c.domain.empty()) {
        if (err)
            *err = "cookie name and domain must be non-empty";
        return false;
    }
    if (line_is_bad(c.name) || line_is_bad(c.value)) {
        if (err)
            *err = "cookie name/value contains tab or newline";
        return false;
    }

    Cookie copy = c;
    copy.domain = normalize_domain(copy.domain);
    if (copy.path.empty())
        copy.path = "/";

    for (auto& existing : cookies_) {
        if (existing.name == copy.name && existing.domain == copy.domain &&
            existing.path == copy.path) {
            existing = std::move(copy);
            return save(err);
        }
    }
    cookies_.push_back(std::move(copy));
    return save(err);
}

std::optional<Cookie> Store::find(const std::string& domain, const std::string& path,
                                  const std::string& name) const {
    for (const auto& c : cookies_) {
        if (c.name == name && c.domain == normalize_domain(domain) && c.path == path) {
            return c;
        }
    }
    return std::nullopt;
}

std::vector<Cookie> Store::for_request(const std::string& host, bool https,
                                       const std::string& path) const {
    const auto now = std::chrono::system_clock::now();
    std::vector<Cookie> out;
    for (const auto& c : cookies_) {
        if (c.expires.has_value() && *c.expires <= now)
            continue;  // expired
        if (c.secure && !https)
            continue;
        if (!domain_matches(c, host))
            continue;
        if (!path_matches(c.path, path))
            continue;
        out.push_back(c);
    }
    std::sort(out.begin(), out.end(), [](const Cookie& a, const Cookie& b) {
        if (a.path.size() != b.path.size())
            return a.path.size() > b.path.size();
        return a.name < b.name;
    });
    return out;
}

bool Store::remove(const std::string& domain, const std::string& name) {
    const std::string d = normalize_domain(domain);
    auto it = cookies_.begin();
    bool removed = false;
    while (it != cookies_.end()) {
        if (it->name == name && it->domain == d) {
            it = cookies_.erase(it);
            removed = true;
        } else {
            ++it;
        }
    }
    return removed;
}

bool Store::save(std::string* err) const {
    std::string content;
    for (const auto& c : cookies_) {
        long exp = !c.expires.has_value()
                       ? 0L
                       : static_cast<long>(std::chrono::system_clock::to_time_t(*c.expires));
        content += c.domain + "\t" + (c.host_only ? "0" : "1") + "\t" + c.path + "\t" +
                   (c.secure ? "1" : "0") + "\t" + std::to_string(exp) + "\t" + c.name + "\t" +
                   c.value + "\n";
    }

    const std::string tmp = dir_ + "/cookies.txt.tmp" + std::to_string(::getpid());
    int fd = ::open(tmp.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) {
        if (err)
            *err = "open temp failed: " + std::string(std::strerror(errno));
        return false;
    }
    size_t off = 0;
    bool ok = true;
    while (off < content.size()) {
        ssize_t n = ::write(fd, content.data() + off, content.size() - off);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            ok = false;
            break;
        }
        off += static_cast<size_t>(n);
    }
    if (ok && (fchmod(fd, 0600) != 0 || fsync(fd) != 0))
        ok = false;
    ::close(fd);
    if (!ok) {
        ::unlink(tmp.c_str());
        if (err)
            *err = "write temp failed: " + std::string(std::strerror(errno));
        return false;
    }
    const std::string fpath = dir_ + "/cookies.txt";
    if (rename(tmp.c_str(), fpath.c_str()) != 0) {
        ::unlink(tmp.c_str());
        if (err)
            *err = "rename failed: " + std::string(std::strerror(errno));
        return false;
    }
    struct stat st{};
    if (stat(fpath.c_str(), &st) != 0 || (st.st_mode & 0777) != 0600) {
        if (err)
            *err = "cookies.txt mode is not 0600 after save";
        return false;
    }
    return true;
}

}  // namespace gp::cookies