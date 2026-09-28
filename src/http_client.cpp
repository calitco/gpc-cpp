#include "gp/http_client.h"

#include <curl/curl.h>

#include <cctype>

namespace gp::http {

struct HttpClient::Impl {
    const SecurityOptions& opts;
    explicit Impl(const SecurityOptions& o) : opts(o) {}
};

namespace {
// Per-request state handed to the curl callbacks (kept out of the private
// Impl so free functions can use it).
struct CurlState {
    std::string* body = nullptr;
    std::size_t body_cap = 0;
    long status_code = 0;
    bool size_cap_hit = false;
    // Header bookkeeping. `current_headers` collects the CURRENT hop's headers;
    // a new "HTTP/" status line starts a new hop and clears it (only the final
    // hop's headers are kept). Set-Cookie values accumulate from all hops into
    // `set_cookies`.
    std::vector<std::pair<std::string, std::string>> current_headers;
    std::vector<std::string>* set_cookies = nullptr;
};

std::string trim(const std::string& s) {
    size_t b = s.find_first_not_of(" \t");
    if (b == std::string::npos)
        return "";
    size_t e = s.find_last_not_of(" \t");
    return s.substr(b, e - b + 1);
}

std::string lowercase(std::string s) {
    for (auto& c : s)
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}

std::size_t write_cb(char* ptr, std::size_t size, std::size_t nmemb, void* userdata) {
    auto* st = static_cast<CurlState*>(userdata);
    std::size_t len = size * nmemb;
    if (st->body->size() + len > st->body_cap) {
        // Abort the transfer: returning a short count makes curl stop.
        st->size_cap_hit = true;
        return 0;
    }
    st->body->append(ptr, len);
    return len;
}

std::size_t header_cb(char* ptr, std::size_t size, std::size_t nmemb, void* userdata) {
    auto* st = static_cast<CurlState*>(userdata);
    std::string line(ptr, size * nmemb);
    // libcurl hands each header line with its terminating CRLF intact; strip it
    // so values never carry control characters (Location, Set-Cookie, ...).
    while (!line.empty() && (line.back() == '\r' || line.back() == '\n'))
        line.pop_back();
    if (line.size() > 5 && line.compare(0, 5, "HTTP/") == 0) {
        try {
            st->status_code = std::stol(trim(line.substr(9)));
        } catch (...) {
            // Malformed status line: keep the old value, never throw into curl.
        }
        // New response hop: reset the header list (final hop wins; the last
        // hop's contents are copied into *headers after perform() returns).
        st->current_headers.clear();
    } else {
        auto colon = line.find(':');
        if (colon != std::string::npos) {
            std::string name = lowercase(trim(line.substr(0, colon)));
            std::string value = trim(line.substr(colon + 1));
            if (name == "set-cookie" && !value.empty()) {
                if (st->set_cookies)
                    st->set_cookies->push_back(value);
            } else if (!name.empty()) {
                st->current_headers.emplace_back(std::move(name), std::move(value));
            }
        }
    }
    // MUST return the number of bytes processed; anything else makes curl
    // abort with CURLE_WRITE_ERROR.
    return static_cast<std::size_t>(size * nmemb);
}

void configure(CURL* c, const SecurityOptions& opts) {
    // Mandatory timeouts (M-2): connect + total.
    curl_easy_setopt(c, CURLOPT_CONNECTTIMEOUT_MS,
                     static_cast<long>(opts.http_connect_timeout.count()));
    curl_easy_setopt(c, CURLOPT_TIMEOUT_MS, static_cast<long>(opts.http_total_timeout.count()));
    // Redirects: follow a bounded number; only http/https protocols.
    curl_easy_setopt(c, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(c, CURLOPT_MAXREDIRS, 5L);
    curl_easy_setopt(c, CURLOPT_PROTOCOLS_STR, "http,https");
    // TLS: verify by default; the old lenient behavior is only reachable via
    // the explicit --ignore-tls-errors switch.
    if (opts.allow_insecure_tls) {
        curl_easy_setopt(c, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(c, CURLOPT_SSL_VERIFYHOST, 0L);
    } else {
        curl_easy_setopt(c, CURLOPT_SSL_VERIFYPEER, 1L);
        curl_easy_setopt(c, CURLOPT_SSL_VERIFYHOST, 2L);
    }
}

HttpResponse perform(const SecurityOptions& opts, const std::string& method, const std::string& url,
                     const std::string* post_body, const std::string* content_type,
                     const RequestOptions& req_opts) {
    HttpResponse res;
    CurlState st;
    st.body = &res.body;
    st.body_cap = opts.max_http_response_bytes;
    st.set_cookies = &res.set_cookie_headers;

    CURL* c = curl_easy_init();
    if (!c) {
        res.error = "curl_easy_init failed";
        return res;
    }
    configure(c, opts);
    if (!req_opts.follow_redirects) {
        // Stateful flows resolve Location themselves so cookies from each hop
        // can be ingested before the next request.
        curl_easy_setopt(c, CURLOPT_FOLLOWLOCATION, 0L);
    }
    curl_easy_setopt(c, CURLOPT_URL, url.c_str());
    curl_easy_setopt(c, CURLOPT_CUSTOMREQUEST, method.c_str());
    curl_easy_setopt(c, CURLOPT_WRITEFUNCTION, write_cb);
    curl_easy_setopt(c, CURLOPT_HEADERFUNCTION, header_cb);
    curl_easy_setopt(c, CURLOPT_WRITEDATA, &st);
    curl_easy_setopt(c, CURLOPT_HEADERDATA, &st);
    struct curl_slist* headers = nullptr;
    if (post_body) {
        curl_easy_setopt(c, CURLOPT_POSTFIELDS, post_body->c_str());
        curl_easy_setopt(c, CURLOPT_POSTFIELDSIZE, static_cast<long>(post_body->size()));
        if (content_type)
            headers = curl_slist_append(headers, ("Content-Type: " + *content_type).c_str());
    }
    for (const auto& h : req_opts.headers) {
        headers = curl_slist_append(headers, (h.first + ": " + h.second).c_str());
    }
    if (headers)
        curl_easy_setopt(c, CURLOPT_HTTPHEADER, headers);

    CURLcode rc = curl_easy_perform(c);
    res.headers = std::move(st.current_headers);  // final hop's headers win
    if (st.size_cap_hit) {
        // The write callback aborted the transfer on overflow.
        res.error = "response exceeded size cap (" + std::to_string(opts.max_http_response_bytes) +
                    " bytes)";
    } else if (rc != CURLE_OK) {
        res.error = curl_easy_strerror(rc);
        if (rc == CURLE_OPERATION_TIMEDOUT)
            res.error = "timeout: " + res.error;
    } else {
        res.ok = true;
    }
    res.status_code = st.status_code;
    if (headers)
        curl_slist_free_all(headers);
    curl_easy_cleanup(c);
    return res;
}
}  // namespace

HttpClient::HttpClient(const SecurityOptions& opts) : impl_(std::make_unique<Impl>(opts)) {}

HttpClient::~HttpClient() = default;

HttpResponse HttpClient::get(const std::string& url, const RequestOptions& opts) {
    return perform(impl_->opts, "GET", url, nullptr, nullptr, opts);
}

HttpResponse HttpClient::post(const std::string& url, const std::string& body,
                              const std::string& content_type, const RequestOptions& opts) {
    return perform(impl_->opts, "POST", url, &body, &content_type, opts);
}

}  // namespace gp::http
