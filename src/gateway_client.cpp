// GlobalProtect gateway API client — see include/gp/gateway_client.h for the
// flow and security properties. This file implements:
//   - a strict minimal HTML form extractor (portal pages are machine-generated)
//   - the four-step stateful flow with manual redirect following and per-hop
//     cookie ingestion
#include "gp/gateway_client.h"

#include <cctype>
#include <cstring>
#include <utility>

#include "gp/trace.h"
#include "gp/xml.h"

namespace gp::gateway {

namespace {

std::string to_lower(std::string s) {
    for (auto& c : s)
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}

bool has_control_chars(const std::string& s) {
    for (unsigned char c : s)
        if (c < 0x20 || c == 0x7f)
            return true;
    return false;
}

// application/x-www-form-urlencoded percent-encoding.
std::string form_encode(const std::string& s) {
    static const char* hex = "0123456789ABCDEF";
    std::string out;
    out.reserve(s.size());
    for (unsigned char c : s) {
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
            c == '-' || c == '_' || c == '.' || c == '~') {
            out += static_cast<char>(c);
        } else if (c == ' ') {
            out += '+';
        } else {
            out += '%';
            out += hex[c >> 4];
            out += hex[c & 15];
        }
    }
    return out;
}

std::string form_encode_fields(const std::vector<std::pair<std::string, std::string>>& fields) {
    std::string out;
    for (size_t i = 0; i < fields.size(); ++i) {
        if (i)
            out += '&';
        out += form_encode(fields[i].first);
        out += '=';
        out += form_encode(fields[i].second);
    }
    return out;
}

// Last occurrence wins (duplicate headers are appended in order).
std::string header_lookup(const http::HttpResponse& res, const std::string& name) {
    std::string found;
    for (const auto& h : res.headers)
        if (h.first == name)
            found = h.second;
    return found;
}
// Root-relative path + query of an absolute URL ("/" when absent).
std::string url_path(const std::string& url) {
    auto scheme_end = url.find("://");
    size_t start = (scheme_end == std::string::npos) ? 0 : scheme_end + 3;
    auto slash = url.find('/', start);
    return (slash == std::string::npos) ? "/" : url.substr(slash);
}

// Path only, query stripped: session tokens (IKEY=..., key=...) ride in
// query strings and must never reach trace lines (M-3).
std::string trace_path(const std::string& url) {
    std::string p = url_path(url);
    auto q = p.find('?');
    if (q != std::string::npos)
        p.resize(q);
    return p;
}

// Decode the five predefined entities plus numeric refs. Unknown references
// are passed through unchanged (HTML is lenient; we must not MISS a '<' or
// '"' hiding inside an entity).
std::string decode_entities(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    size_t i = 0;
    while (i < s.size()) {
        if (s[i] != '&') {
            out += s[i++];
            continue;
        }
        auto semi = s.find(';', i);
        if (semi == std::string::npos || semi - i > 12) {
            out += s[i++];  // not a reference: literal '&'
            continue;
        }
        std::string ref = s.substr(i + 1, semi - i - 1);
        if (ref == "amp")
            out += '&';
        else if (ref == "lt")
            out += '<';
        else if (ref == "gt")
            out += '>';
        else if (ref == "quot")
            out += '"';
        else if (ref == "apos")
            out += '\'';
        else if (!ref.empty() && ref[0] == '#') {
            unsigned long cp = 0;
            bool ok = false;
            try {
                size_t digits = 2;
                int base = 16;
                if (!(ref.size() > 2 && (ref[1] == 'x' || ref[1] == 'X'))) {
                    digits = 1;
                    base = 10;
                }
                std::string num = ref.substr(digits);
                if (!num.empty()) {
                    size_t consumed = 0;
                    cp = std::stoul(num, &consumed, base);
                    ok = (consumed == num.size() && cp > 0 && cp <= 0x10FFFF);
                }
            } catch (...) {
                ok = false;
            }
            if (!ok) {
                out += s[i++];
                continue;
            }
            // UTF-8 encode (portal values are ASCII in practice; anything above
            // 0x7F is encoded so the byte stream stays well-formed).
            if (cp < 0x80) {
                out += static_cast<char>(cp);
            } else if (cp < 0x800) {
                out += static_cast<char>(0xC0 | (cp >> 6));
                out += static_cast<char>(0x80 | (cp & 0x3F));
            } else if (cp < 0x10000) {
                out += static_cast<char>(0xE0 | (cp >> 12));
                out += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
                out += static_cast<char>(0x80 | (cp & 0x3F));
            } else {
                out += static_cast<char>(0xF0 | (cp >> 18));
                out += static_cast<char>(0x80 | ((cp >> 12) & 0x3F));
                out += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
                out += static_cast<char>(0x80 | (cp & 0x3F));
            }
        } else {
            out += s[i++];  // unknown entity name: literal
            continue;
        }
        i = semi + 1;
    }
    return out;
}

// Parse the attribute list of a tag. `body` is the text after the tag name,
// up to and including its closing '>'. *ok is set false on an unterminated
// quoted value (the document is malformed for our purposes).
std::vector<std::pair<std::string, std::string>> parse_tag_attrs(const std::string& body,
                                                                 bool* ok) {
    std::vector<std::pair<std::string, std::string>> attrs;
    size_t i = 0;
    while (i < body.size()) {
        while (i < body.size() && std::isspace(static_cast<unsigned char>(body[i])))
            i++;
        if (i >= body.size() || body[i] == '>' || body[i] == '/')
            break;
        size_t n0 = i;
        while (i < body.size() && !std::isspace(static_cast<unsigned char>(body[i])) &&
               body[i] != '=' && body[i] != '>' && body[i] != '/') {
            i++;
        }
        std::string name = to_lower(body.substr(n0, i - n0));
        if (name.empty()) {
            i++;  // stray character: skip one byte and keep going
            continue;
        }
        while (i < body.size() && std::isspace(static_cast<unsigned char>(body[i])))
            i++;
        std::string value;
        if (i < body.size() && body[i] == '=') {
            i++;
            while (i < body.size() && std::isspace(static_cast<unsigned char>(body[i])))
                i++;
            if (i < body.size() && (body[i] == '"' || body[i] == '\'')) {
                char q = body[i++];
                auto e = body.find(q, i);
                if (e == std::string::npos) {
                    *ok = false;  // unterminated quote: document malformed
                    return attrs;
                }
                value = body.substr(i, e - i);
                i = e + 1;
            } else {
                size_t v0 = i;
                while (i < body.size() && !std::isspace(static_cast<unsigned char>(body[i])) &&
                       body[i] != '>') {
                    i++;
                }
                value = body.substr(v0, i - v0);
            }
        }
        attrs.emplace_back(std::move(name), std::move(value));
    }
    return attrs;
}

// Quote-aware scan for the closing '>' of a tag starting at `start`.
size_t find_tag_end(const std::string& s, size_t start) {
    char quote = 0;
    for (size_t i = start; i < s.size(); ++i) {
        if (quote) {
            if (s[i] == quote)
                quote = 0;
        } else if (s[i] == '"' || s[i] == '\'') {
            quote = s[i];
        } else if (s[i] == '>') {
            return i;
        }
    }
    return std::string::npos;
}

// Case-insensitive find of "<name" where the next char is whitespace, '>', or
// '/' (so <formaction does not match <form).
size_t find_tag(const std::string& s, const std::string& name, size_t from) {
    std::string needle = "<" + name;
    size_t i = from;
    while ((i = s.find(needle, i)) != std::string::npos) {
        char c = (i + needle.size() < s.size()) ? s[i + needle.size()] : '\0';
        if (c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '>' || c == '/') {
            return i;
        }
        i += needle.size();
    }
    return std::string::npos;
}

const std::pair<std::string, std::string>* attr_get(
    const std::vector<std::pair<std::string, std::string>>& attrs, const std::string& name) {
    for (const auto& a : attrs)
        if (a.first == name)
            return &a;
    return nullptr;
}

}  // namespace

bool parse_html_form(const std::string& html, size_t max_bytes, HtmlForm* out, std::string* err) {
    auto fail = [&](const std::string& msg) {
        if (err)
            *err = msg;
        return false;
    };
    if (html.size() > max_bytes)
        return fail("form document exceeds size cap");
    if (html.find('\0') != std::string::npos)
        return fail("NUL byte in form document");

    size_t fstart = find_tag(html, "form", 0);
    if (fstart == std::string::npos)
        return fail("no <form> element found");
    size_t fend = find_tag_end(html, fstart + 4);
    if (fend == std::string::npos)
        return fail("unterminated <form> tag");

    bool attrs_ok = true;
    auto attrs = parse_tag_attrs(html.substr(fstart + 4, fend - fstart - 4), &attrs_ok);
    if (!attrs_ok)
        return fail("malformed attribute in <form> tag");

    // method: require explicit POST. Submitting credentials via GET would put
    // them in the URL (proxy logs, Referer headers) — fail closed instead.
    const auto* m = attr_get(attrs, "method");
    if (!m || to_lower(decode_entities(m->second)) != "post") {
        return fail("form is not method=post; refusing to submit credentials");
    }

    // action: must be a root-relative path. Rejects absolute URLs,
    // protocol-relative "//host/...", and any scheme (javascript:, data:, ...).
    const auto* a = attr_get(attrs, "action");
    if (!a)
        return fail("form has no action attribute");
    std::string action = decode_entities(a->second);
    // Trim surrounding whitespace.
    size_t ab = action.find_first_not_of(" \t\r\n");
    if (ab == std::string::npos)
        return fail("empty form action");
    size_t ae = action.find_last_not_of(" \t\r\n");
    action = action.substr(ab, ae - ab + 1);
    if (action.size() < 2 || action[0] != '/' || action[1] == '/') {
        return fail("form action is not a root-relative path; refusing");
    }
    if (has_control_chars(action))
        return fail("control character in form action");

    HtmlForm form;
    form.action = std::move(action);
    form.method_post = true;

    // Hidden inputs between the opening tag and </form> (or end of document).
    size_t range_start = fend + 1;
    size_t range_end = html.size();
    for (size_t i = find_tag(html, "/form", range_start); i != std::string::npos && i < range_end;
         i = find_tag(html, "/form", i + 5)) {
        if (i + 6 < html.size() && html[i + 6] == '>')
            range_end = i;
    }

    size_t pos = range_start;
    while ((pos = find_tag(html, "input", pos)) != std::string::npos && pos < range_end) {
        size_t iend = find_tag_end(html, pos + 5);
        if (iend == std::string::npos)
            return fail("unterminated <input> tag");
        bool iok = true;
        auto iattrs = parse_tag_attrs(html.substr(pos + 5, iend - pos - 5), &iok);
        if (!iok)
            return fail("malformed attribute in <input> tag");
        pos = iend + 1;

        const auto* t = attr_get(iattrs, "type");
        if (!t || to_lower(decode_entities(t->second)) != "hidden")
            continue;
        const auto* n = attr_get(iattrs, "name");
        if (!n)
            continue;
        std::string name = decode_entities(n->second);
        std::string value;
        if (const auto* v = attr_get(iattrs, "value")) {
            value = decode_entities(v->second);
        }
        if (has_control_chars(name) || has_control_chars(value)) {
            return fail("control character in hidden input name/value");
        }
        form.fields.emplace_back(std::move(name), std::move(value));
    }

    *out = std::move(form);
    return true;
}

namespace {

// Hostname (without port) of a base_url like "https://gw.example.com:8443".
std::string host_of(const std::string& base_url) {
    auto scheme_end = base_url.find("://");
    size_t start = (scheme_end == std::string::npos) ? 0 : scheme_end + 3;
    auto slash = base_url.find('/', start);
    std::string hostport = (slash == std::string::npos) ? base_url.substr(start)
                                                        : base_url.substr(start, slash - start);
    auto colon = hostport.rfind(':');
    return (colon == std::string::npos) ? hostport : hostport.substr(0, colon);
}

}  // namespace

GatewayClient::GatewayClient(SecurityOptions opts, GatewayConfig cfg, cookies::Store store)
    : opts_(std::move(opts)), cfg_(std::move(cfg)), http_(opts_), store_(std::move(store)) {}

std::unique_ptr<GatewayClient> GatewayClient::create(const SecurityOptions& opts,
                                                     const GatewayConfig& cfg,
                                                     const std::string& cookie_dir,
                                                     std::string* err) {
    auto fail = [&](const std::string& msg) {
        if (err)
            *err = msg;
        return std::unique_ptr<GatewayClient>();
    };
    if (cfg.gateway_host.empty())
        return fail("gateway_host is empty");
    bool https = cfg.base_url.rfind("https://", 0) == 0;
    bool plain_http = cfg.base_url.rfind("http://", 0) == 0;
    if (!https && !plain_http) {
        return fail("base_url must start with http:// or https://");
    }
    if (!cfg.base_url.empty() && cfg.base_url.back() == '/') {
        return fail("base_url must not have a trailing slash");
    }
    if (host_of(cfg.base_url).empty())
        return fail("base_url has no host");

    std::string serr;
    cookies::Store store = cookies::Store::open(cookie_dir, &serr);
    if (!store.ok())
        return fail("cookie store: " + serr);

    return std::unique_ptr<GatewayClient>(new GatewayClient(opts, cfg, std::move(store)));
}

void GatewayClient::ingest_cookies(const http::HttpResponse& res) {
    for (const auto& sc : res.set_cookie_headers) {
        auto c = cookies::parse_set_cookie(sc, host_of(cfg_.base_url));
        if (c) {
            store_.set(*c);  // malformed values are skipped, never fatal
            GP_TRACE("cookies: stored '", c->name, "'");  // name only, never the value
        }
    }
}

bool GatewayClient::resolve_location(const std::string& location, std::string* out,
                                     std::string* err) const {
    auto fail = [&](const std::string& msg) {
        if (err)
            *err = msg;
        return false;
    };
    // Trim.
    size_t b = location.find_first_not_of(" \t\r\n");
    if (b == std::string::npos)
        return fail("empty Location header");
    size_t e = location.find_last_not_of(" \t\r\n");
    std::string loc = location.substr(b, e - b + 1);
    if (has_control_chars(loc))
        return fail("Location contains control characters");

    if (loc.rfind("https://", 0) == 0 || loc.rfind("http://", 0) == 0) {
        // Absolute: must be exactly our origin (scheme + host[:port]).
        std::string origin = cfg_.base_url;
        auto slash = origin.find('/', origin.find("://") + 3);
        if (slash != std::string::npos)
            origin.resize(slash);
        std::string loc_origin = loc;
        auto lslash = loc.find('/', loc.find("://") + 3);
        if (lslash != std::string::npos)
            loc_origin.resize(lslash);
        if (to_lower(loc_origin) != to_lower(origin)) {
            return fail("redirect to foreign origin refused (cookies would leak)");
        }
        *out = loc;
        return true;
    }
    if (!loc.empty() && loc[0] == '/') {
        *out = cfg_.base_url + loc;
        return true;
    }
    // Protocol-relative ("//host/...") and any scheme: refused.
    return fail("Location is not root-relative or same-origin; refusing");
}

namespace {

// Build the "Cookie:" header value from the jar (values were control-char
// checked at parse time, so this cannot inject headers).
std::string cookie_header(const std::vector<cookies::Cookie>& cs) {
    std::string header;
    for (size_t i = 0; i < cs.size(); ++i) {
        if (i)
            header += "; ";
        header += cs[i].name;
        header += '=';
        header += cs[i].value;
    }
    return header;
}

}  // namespace

http::HttpResponse GatewayClient::get(const std::string& url, std::string* err) {
    http::RequestOptions ropts;
    ropts.follow_redirects = false;  // we follow manually (cookie ingestion per hop)
    auto cs = store_.for_request(host_of(cfg_.base_url), cfg_.base_url.rfind("https://", 0) == 0,
                                 url_path(url));
    if (!cs.empty())
        ropts.headers.emplace_back("Cookie", cookie_header(cs));
    http::HttpResponse res = http_.get(url, ropts);
    if (res.ok) {
        GP_TRACE("http: GET ", trace_path(url), " -> HTTP ", res.status_code, " (", res.body.size(),
                 " bytes)");
    } else {
        GP_TRACE("http: GET ", trace_path(url), " failed: ", res.error);
        if (err)
            *err = "GET " + url_path(url) + ": " + res.error;
    }
    return res;
}

http::HttpResponse GatewayClient::post(
    const std::string& url, const std::vector<std::pair<std::string, std::string>>& fields,
    std::string* err) {
    http::RequestOptions ropts;
    ropts.follow_redirects = false;
    auto cs = store_.for_request(host_of(cfg_.base_url), cfg_.base_url.rfind("https://", 0) == 0,
                                 url_path(url));
    if (!cs.empty())
        ropts.headers.emplace_back("Cookie", cookie_header(cs));
    http::HttpResponse res =
        http_.post(url, form_encode_fields(fields), "application/x-www-form-urlencoded", ropts);
    if (res.ok) {
        GP_TRACE("http: POST ", trace_path(url), " (", fields.size(), " fields) -> HTTP ",
                 res.status_code, " (", res.body.size(), " bytes)");
    } else {
        GP_TRACE("http: POST ", trace_path(url), " failed: ", res.error);
        if (err)
            *err = "POST " + url_path(url) + ": " + res.error;
    }
    return res;
}

bool GatewayClient::prelogin(std::string* err) {
    std::string url =
        cfg_.base_url + "/sslvpnd/prelogin.xml?server=" + form_encode(cfg_.gateway_host);
    http::HttpResponse res = get(url, err);
    if (!res.ok)
        return false;
    ingest_cookies(res);
    if (res.status_code != 200) {
        if (err)
            *err = "prelogin: HTTP " + std::to_string(res.status_code);
        return false;
    }
    xml::Element root;
    std::string xerr;
    if (!xml::parse_xml(res.body, opts_.max_http_response_bytes, &root, &xerr)) {
        if (err)
            *err = "prelogin: malformed XML: " + xerr;
        return false;
    }
    if (root.name != "prelogin") {
        if (err)
            *err = "prelogin: unexpected root element <" + root.name + ">";
        return false;
    }
    const xml::Element* sid = root.child("session_id");
    if (!sid) {
        if (err)
            *err = "prelogin: missing <session_id>";
        return false;
    }
    session_id_ = sid->text_trim();
    if (session_id_.empty()) {
        if (err)
            *err = "prelogin: empty session id";
        return false;
    }
    if (has_control_chars(session_id_)) {
        if (err)
            *err = "prelogin: session id contains control characters";
        session_id_.clear();
        return false;
    }
    GP_TRACE("prelogin: session established");
    return true;
}

bool GatewayClient::login(const std::string& username, const std::string& password,
                          std::string* err) {
    // NOTE: `username`/`password` are used ONLY in the POST body below. Nothing
    // in this function copies them into error strings (H-3/M-3).

    // -- Form discovery -------------------------------------------------------
    std::string url = cfg_.base_url + "/sslvpn-login";
    http::HttpResponse res;
    for (int hop = 0;; ++hop) {
        res = get(url, err);
        if (!res.ok)
            return false;
        ingest_cookies(res);
        if (res.status_code >= 300 && res.status_code < 400) {
            if (hop >= cfg_.max_redirects) {
                if (err)
                    *err = "login: too many redirects";
                return false;
            }
            std::string loc = header_lookup(res, "location");
            if (loc.empty()) {
                if (err)
                    *err = "login: redirect without Location";
                return false;
            }
            if (!resolve_location(loc, &url, err))
                return false;
            continue;
        }
        break;
    }
    if (res.status_code != 200) {
        if (err)
            *err = "login: form discovery got HTTP " + std::to_string(res.status_code);
        return false;
    }
    HtmlForm form;
    std::string ferr;
    if (!parse_html_form(res.body, opts_.max_http_response_bytes, &form, &ferr)) {
        if (err)
            *err = "login: " + ferr;
        return false;
    }
    GP_TRACE("login: form discovered (", form.fields.size(), " hidden fields)");

    // -- Credential POST ------------------------------------------------------
    std::vector<std::pair<std::string, std::string>> fields = form.fields;
    bool has_ikey = false;
    for (const auto& f : fields)
        if (f.first == "IKEY")
            has_ikey = true;
    if (!has_ikey && !session_id_.empty())
        fields.emplace_back("IKEY", session_id_);
    fields.emplace_back("username", username);
    fields.emplace_back("password", password);

    std::string action_url;
    if (!resolve_location(form.action, &action_url, err))
        return false;
    url = action_url;
    GP_TRACE("login: submitting credentials to ", trace_path(action_url));
    bool first_hop = true;
    for (int hop = 0;; ++hop) {
        // After the credential POST, redirects are followed with GET so the
        // password is transmitted exactly once.
        res = first_hop ? post(url, fields, err) : get(url, err);
        first_hop = false;
        if (!res.ok)
            return false;
        ingest_cookies(res);
        if (res.status_code >= 300 && res.status_code < 400) {
            if (hop >= cfg_.max_redirects) {
                if (err)
                    *err = "login: too many redirects";
                return false;
            }
            std::string loc = header_lookup(res, "location");
            if (loc.empty()) {
                if (err)
                    *err = "login: redirect without Location";
                return false;
            }
            if (!resolve_location(loc, &url, err))
                return false;
            continue;
        }
        break;
    }
    if (res.status_code < 200 || res.status_code >= 300) {
        // Deliberately generic: no credentials, no response body.
        if (err)
            *err = "login rejected by gateway (HTTP " + std::to_string(res.status_code) + ")";
        return false;
    }
    GP_TRACE("login: accepted (HTTP ", res.status_code, ")");
    return true;
}

bool GatewayClient::saml_login(const std::string& payload, const std::string& return_path,
                               const std::string& field_name, std::string* err) {
    // NOTE: `payload` is used ONLY in the POST body below. Nothing in this
    // function copies it into error strings (H-3/M-3).
    if (session_id_.empty()) {
        if (err)
            *err = "saml_login: prelogin() must succeed first";
        return false;
    }
    if (return_path.empty() || return_path[0] != '/' || has_control_chars(return_path)) {
        if (err)
            *err =
                "saml_login: return path must be a root-relative path without control characters";
        return false;
    }
    if (field_name.empty() || has_control_chars(field_name)) {
        if (err)
            *err = "saml_login: invalid field name";
        return false;
    }

    std::vector<std::pair<std::string, std::string>> fields = {{field_name, payload}};
    std::string url = cfg_.base_url + return_path;
    GP_TRACE("saml_login: posting callback payload to ", return_path, " as '", field_name, "' (",
             payload.size(), " bytes)");
    http::HttpResponse res;
    bool first_hop = true;
    for (int hop = 0;; ++hop) {
        // After the SAML POST, redirects are followed with GET so the payload is
        // transmitted exactly once.
        res = first_hop ? post(url, fields, err) : get(url, err);
        first_hop = false;
        if (!res.ok)
            return false;
        ingest_cookies(res);
        if (res.status_code >= 300 && res.status_code < 400) {
            if (hop >= cfg_.max_redirects) {
                if (err)
                    *err = "saml_login: too many redirects";
                return false;
            }
            std::string loc = header_lookup(res, "location");
            if (loc.empty()) {
                if (err)
                    *err = "saml_login: redirect without Location";
                return false;
            }
            if (!resolve_location(loc, &url, err))
                return false;
            continue;
        }
        break;
    }
    if (res.status_code < 200 || res.status_code >= 300) {
        // Deliberately generic: no payload, no response body.
        if (err)
            *err = "saml_login rejected by gateway (HTTP " + std::to_string(res.status_code) + ")";
        return false;
    }
    GP_TRACE("saml_login: accepted (HTTP ", res.status_code, ")");
    return true;
}

bool GatewayClient::connect(std::string* err) {
    if (session_id_.empty()) {
        if (err)
            *err = "connect: prelogin() must succeed first";
        return false;
    }
    // -- Portal page ----------------------------------------------------------
    std::string url = cfg_.base_url +
                      "/portal/index.html?server=" + form_encode(cfg_.gateway_host) +
                      "&IKEY=" + form_encode(session_id_);
    http::HttpResponse res;
    for (int hop = 0;; ++hop) {
        res = get(url, err);
        if (!res.ok)
            return false;
        ingest_cookies(res);
        if (res.status_code >= 300 && res.status_code < 400) {
            if (hop >= cfg_.max_redirects) {
                if (err)
                    *err = "connect: too many redirects";
                return false;
            }
            std::string loc = header_lookup(res, "location");
            if (loc.empty()) {
                if (err)
                    *err = "connect: redirect without Location";
                return false;
            }
            if (!resolve_location(loc, &url, err))
                return false;
            continue;
        }
        break;
    }
    if (res.status_code != 200) {
        if (err)
            *err = "connect: portal page got HTTP " + std::to_string(res.status_code);
        return false;
    }
    HtmlForm form;
    std::string ferr;
    if (!parse_html_form(res.body, opts_.max_http_response_bytes, &form, &ferr)) {
        if (err)
            *err = "connect: " + ferr;
        return false;
    }
    GP_TRACE("connect: portal form discovered (", form.fields.size(), " hidden fields)");

    // -- Connect POST (single hop: the response itself names the endpoint) ----
    std::vector<std::pair<std::string, std::string>> fields = form.fields;
    for (const auto& f : cfg_.connect_extra_fields)
        fields.push_back(f);

    std::string action_url;
    if (!resolve_location(form.action, &action_url, err))
        return false;
    GP_TRACE("connect: posting portal form to ", trace_path(action_url));
    res = post(action_url, fields, err);
    if (!res.ok)
        return false;
    ingest_cookies(res);

    tunnel_endpoint_.clear();
    if (res.status_code >= 300 && res.status_code < 400) {
        std::string loc = header_lookup(res, "location");
        if (loc.empty()) {
            if (err)
                *err = "connect: redirect without Location";
            return false;
        }
        if (!resolve_location(loc, &tunnel_endpoint_, err))
            return false;
    } else if (res.status_code >= 200 && res.status_code < 300) {
        // Endpoint in the body: a form whose action is the tunnel path.
        HtmlForm f2;
        std::string ferr2;
        if (!parse_html_form(res.body, opts_.max_http_response_bytes, &f2, &ferr2)) {
            if (err)
                *err = "connect: no tunnel endpoint in portal response";
            return false;
        }
        if (!resolve_location(f2.action, &tunnel_endpoint_, err))
            return false;
    } else {
        if (err)
            *err = "connect: HTTP " + std::to_string(res.status_code);
        return false;
    }

    // Remember the portal form for extend_session(). The endpoint is already
    // printed by gpclient on success, so tracing it adds no new exposure.
    GP_TRACE("connect: tunnel endpoint = ", tunnel_endpoint_);
    have_portal_form_ = true;
    portal_action_ = action_url;
    portal_fields_ = std::move(fields);
    return true;
}

bool GatewayClient::extend_session(std::string* err) {
    if (!have_portal_form_) {
        if (err)
            *err = "extend_session: connect() must succeed first";
        return false;
    }
    http::HttpResponse res = post(portal_action_, portal_fields_, err);
    if (!res.ok)
        return false;
    ingest_cookies(res);
    // Both a fresh page (2xx) and an endpoint redirect (3xx) mean the gateway
    // accepted the session.
    long sc = res.status_code;
    if (sc < 200 || sc >= 400) {
        if (err)
            *err = "extend_session: HTTP " + std::to_string(sc);
        return false;
    }
    GP_TRACE("extend_session: renewed (HTTP ", sc, ")");
    return true;
}

}  // namespace gp::gateway