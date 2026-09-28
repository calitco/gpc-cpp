// Tests for Wave F: gateway API client (prelogin XML, login flow, portal
// exchange, session extension) plus the strict HTML form extractor and the
// Set-Cookie parser. All flows run against a local loopback HTTP server with
// fixture responses — no real gateway is involved.
#include <gp/cookie_store.h>
#include <gp/gateway_client.h>
#include <gp/security_options.h>

#include <cctype>
#include <cstdlib>
#include <functional>
#include <mutex>
#include <thread>
#include <vector>

#include "net_common.h"  // internal helper, exposed for tests
#include "test_framework.h"

using gp::SecurityOptions;
using gp::gateway::GatewayClient;
using gp::gateway::GatewayConfig;
using gp::gateway::HtmlForm;
using gp::gateway::parse_html_form;

namespace {

std::string http_response(
    int status, const std::string& body,
    const std::vector<std::pair<std::string, std::string>>& extra_headers = {}) {
    static const char* reasons[] = {"OK",        "Found",     "Unauthorized",
                                    "Forbidden", "Not Found", "Internal Server Error"};
    int idx = status == 200   ? 0
              : status == 302 ? 1
              : status == 401 ? 2
              : status == 403 ? 3
              : status == 404 ? 4
                              : 5;
    std::string resp = "HTTP/1.1 " + std::to_string(status) + " " + reasons[idx] + "\r\n";
    for (const auto& h : extra_headers) {
        resp += h.first + ": " + h.second + "\r\n";
    }
    resp += "Content-Length: " + std::to_string(body.size()) + "\r\n";
    resp += "Connection: close\r\n\r\n";
    resp += body;
    return resp;
}

// Reads one full HTTP request (headers + Content-Length body) from `fd`.
std::string read_request(int fd) {
    std::string buf;
    char tmp[4096];
    while (buf.find("\r\n\r\n") == std::string::npos) {
        ssize_t n = ::recv(fd, tmp, sizeof(tmp), 0);
        if (n <= 0)
            return buf;
        buf.append(tmp, static_cast<std::size_t>(n));
    }
    auto sep = buf.find("\r\n\r\n");
    std::string head = buf.substr(0, sep);
    long content_length = 0;
    size_t line_start = 0;
    while (line_start < head.size()) {
        auto line_end = head.find("\r\n", line_start);
        std::string line = head.substr(line_start, line_end - line_start);
        auto colon = line.find(':');
        if (colon != std::string::npos) {
            std::string name = line.substr(0, colon);
            for (auto& c : name)
                c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
            if (name == "content-length")
                content_length = std::atol(line.c_str() + colon + 1);
        }
        line_start = (line_end == std::string::npos) ? head.size() : line_end + 2;
    }
    long have = static_cast<long>(buf.size() - sep - 4);
    while (have < content_length) {
        ssize_t n = ::recv(fd, tmp, sizeof(tmp), 0);
        if (n <= 0)
            break;
        buf.append(tmp, static_cast<std::size_t>(n));
        have += n;
    }
    return buf;
}

struct ParsedReq {
    std::string method;
    std::string path;
    std::string body;
    std::vector<std::pair<std::string, std::string>> headers;  // names lowercased

    std::string header(const std::string& name) const {
        std::string found;
        for (const auto& h : headers)
            if (h.first == name)
                found = h.second;
        return found;
    }
};

ParsedReq parse_request(const std::string& raw) {
    ParsedReq r;
    auto sep = raw.find("\r\n\r\n");
    if (sep == std::string::npos)
        return r;
    std::string head = raw.substr(0, sep);
    r.body = raw.substr(sep + 4);
    size_t line_start = 0;
    bool first = true;
    while (line_start < head.size()) {
        auto line_end = head.find("\r\n", line_start);
        std::string line = head.substr(line_start, line_end - line_start);
        if (first) {
            // "METHOD PATH HTTP/1.1"
            auto sp1 = line.find(' ');
            auto sp2 = line.rfind(' ');
            if (sp1 != std::string::npos && sp2 > sp1) {
                r.method = line.substr(0, sp1);
                r.path = line.substr(sp1 + 1, sp2 - sp1 - 1);
            }
            first = false;
        } else if (!line.empty()) {
            auto colon = line.find(':');
            if (colon != std::string::npos) {
                std::string name = line.substr(0, colon);
                for (auto& c : name)
                    c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
                std::string value = line.substr(colon + 1);
                size_t b = value.find_first_not_of(" \t");
                if (b != std::string::npos)
                    value = value.substr(b);
                r.headers.emplace_back(std::move(name), std::move(value));
            }
        }
        line_start = (line_end == std::string::npos) ? head.size() : line_end + 2;
    }
    return r;
}

// Sequential multi-request loopback HTTP server. Each connection gets exactly
// one request; the handler receives the fd and the raw request text and sends
// the response (the server closes the fd afterwards).
struct MultiServer {
    gp::net::TcpListener listener;
    std::thread thread;
    uint16_t port = 0;
    std::vector<std::string> requests;
    std::mutex mu;

    // The serving thread captures `this`, so this must not be copied/moved.
    MultiServer() = default;
    MultiServer(const MultiServer&) = delete;
    MultiServer& operator=(const MultiServer&) = delete;

    bool start(std::function<void(int, const std::string&)> handler, int max_requests = 8) {
        if (!listener.bind_to("127.0.0.1", 0))
            return false;
        port = listener.port();
        thread = std::thread([this, handler, max_requests] {
            for (int i = 0; i < max_requests; ++i) {
                int cfd = listener.accept_with_timeout(5000);
                if (cfd < 0)
                    break;
                std::string raw = read_request(cfd);
                {
                    std::lock_guard<std::mutex> lk(mu);
                    requests.push_back(raw);
                }
                handler(cfd, raw);
                ::close(cfd);
            }
        });
        return true;
    }

    // Requests so far, parsed. Safe to call after a synchronous client call
    // returns (all handlers have completed by then).
    std::vector<ParsedReq> parsed() {
        std::lock_guard<std::mutex> lk(mu);
        std::vector<ParsedReq> out;
        for (const auto& r : requests)
            out.push_back(parse_request(r));
        return out;
    }

    ~MultiServer() {
        listener.close_fd();
        if (thread.joinable())
            thread.join();
    }
};

std::string tmp_dir(const char* tag) {
    char tmpl[] = "/tmp/gp_gateway_test_XXXXXX";
    char* d = mkdtemp(tmpl);
    return d ? std::string(d) + "_" + tag : "";
}

}  // namespace

// ---- parse_html_form -------------------------------------------------------

TEST(gateway_form, parses_post_form_with_hidden_fields_and_entities) {
    const std::string html =
        "<html><body>"
        "<form action=\"/sslvpn/conn\" method=\"post\">"
        "<input type=\"hidden\" name=\"IKEY\" value=\"abc&amp;def\">"
        "<input type=\"text\" name=\"ignored\" value=\"visible\">"
        "<input type=\"hidden\" name=\"n2\" value=\"A&#65;x\">"
        "</form></body></html>";
    HtmlForm f;
    std::string err;
    CHECK(parse_html_form(html, 1 << 20, &f, &err));
    CHECK_EQ(f.action, std::string("/sslvpn/conn"));
    CHECK(f.method_post);
    CHECK_EQ(f.fields.size(), (size_t)2);
    CHECK_EQ(f.fields[0].first, std::string("IKEY"));
    CHECK_EQ(f.fields[0].second, std::string("abc&def"));
    CHECK_EQ(f.fields[1].first, std::string("n2"));
    CHECK_EQ(f.fields[1].second, std::string("AAx"));
}

TEST(gateway_form, rejects_missing_form_and_get_method) {
    HtmlForm f;
    std::string err;
    CHECK(!parse_html_form("<html>no form here</html>", 1 << 20, &f, &err));
    CHECK(!err.empty());

    // HTML default method is GET — submitting credentials via URL is unsafe.
    CHECK(!parse_html_form(
        "<form action=\"/x\"><input type=\"hidden\" name=\"a\" value=\"b\"></form>", 1 << 20, &f,
        &err));
    CHECK(err.find("post") != std::string::npos);

    // <formaction must not match <form.
    CHECK(!parse_html_form("<div formaction=\"/x\"></div>", 1 << 20, &f, &err));
}

TEST(gateway_form, rejects_unsafe_actions) {
    HtmlForm f;
    std::string err;
    const std::vector<std::string> bad = {
        "javascript:alert(1)",   // scheme
        "//evil.example/x",      // protocol-relative (host in second position)
        "https://gw.example/x",  // absolute URL (must be root-relative)
        "relative/path",         // not root-relative
        "/",                     // too short to be a path with a component
    };
    for (const auto& a : bad) {
        err.clear();
        CHECK(!parse_html_form("<form action=\"" + a + "\" method=\"post\"></form>", 1 << 20, &f,
                               &err));
        CHECK(err.find("action") != std::string::npos);
    }
}

TEST(gateway_form, rejects_control_chars_nul_and_oversize) {
    HtmlForm f;
    std::string err;

    // CRLF in a hidden value (would inject into the re-encoded body / logs).
    CHECK(
        !parse_html_form("<form action=\"/x\" method=\"post\">"
                         "<input type=\"hidden\" name=\"a\" value=\"v\r\nX-Injected: 1\"></form>",
                         1 << 20, &f, &err));

    // CRLF in the action.
    CHECK(!parse_html_form("<form action=\"/x\r\nX-Injected: 1\" method=\"post\"></form>", 1 << 20,
                           &f, &err));

    // NUL byte anywhere in the document.
    CHECK(!parse_html_form("<form action=\"/x\" method=\"post\"\0></form>", 1 << 20, &f, &err));

    // Size cap.
    std::string big = "<form action=\"/x\" method=\"post\">";
    big.append(4096, 'p');
    big += "</form>";
    CHECK(!parse_html_form(big, 1024, &f, &err));
    CHECK(err.find("size cap") != std::string::npos);

    // Unterminated form tag.
    CHECK(!parse_html_form("<form action=\"/x\" method=\"post", 1 << 20, &f, &err));
}

TEST(gateway_form, only_collects_inputs_inside_the_form) {
    const std::string html =
        "<input type=\"hidden\" name=\"outside\" value=\"1\">"
        "<form action=\"/x\" method=\"post\">"
        "<input type=\"hidden\" name=\"inside\" value=\"2\">"
        "</form>"
        "<input type=\"hidden\" name=\"after\" value=\"3\">";
    HtmlForm f;
    std::string err;
    CHECK(parse_html_form(html, 1 << 20, &f, &err));
    CHECK_EQ(f.fields.size(), (size_t)1);
    CHECK_EQ(f.fields[0].first, std::string("inside"));
}

// ---- parse_set_cookie ------------------------------------------------------

TEST(gateway_cookie, parses_basic_pair_host_only_default) {
    auto c = gp::cookies::parse_set_cookie("IKEY=abc123", "gw.example.com");
    REQUIRE(c.has_value());
    CHECK_EQ(c->name, std::string("IKEY"));
    CHECK_EQ(c->value, std::string("abc123"));
    CHECK_EQ(c->domain, std::string("gw.example.com"));
    CHECK(c->host_only);
    CHECK_EQ(c->path, std::string("/"));
    CHECK(!c->secure);
    CHECK(!c->http_only);
    CHECK(!c->expires.has_value());
}

TEST(gateway_cookie, parses_attributes) {
    auto c = gp::cookies::parse_set_cookie(
        "SESSION=xyz; Domain=.Example.COM; Path=/portal/; Secure; HttpOnly", "gw.example.com");
    REQUIRE(c.has_value());
    CHECK_EQ(c->domain, std::string("example.com"));  // lowercased, dot stripped
    CHECK(!c->host_only);
    CHECK_EQ(c->path, std::string("/portal/"));
    CHECK(c->secure);
    CHECK(c->http_only);

    // Quoted value is unquoted.
    auto q = gp::cookies::parse_set_cookie("A=\"b c\"", "h");
    REQUIRE(q.has_value());
    CHECK_EQ(q->value, std::string("b c"));
}

TEST(gateway_cookie, max_age_overrides_expires_and_zero_is_expired) {
    // Max-Age wins over Expires.
    auto c = gp::cookies::parse_set_cookie("A=1; Expires=Thu, 31 Dec 2099 23:59:59 GMT; Max-Age=60",
                                           "h");
    REQUIRE(c.has_value());
    REQUIRE(c->expires.has_value());
    auto now = std::chrono::system_clock::now();
    CHECK(*c->expires > now);
    CHECK(*c->expires < now + std::chrono::seconds(120));

    // Max-Age=0 => already expired (epoch).
    auto e = gp::cookies::parse_set_cookie("A=1; Max-Age=0", "h");
    REQUIRE(e.has_value());
    REQUIRE(e->expires.has_value());
    CHECK(*e->expires <= now);

    // Unparseable Expires is ignored => session cookie.
    auto u = gp::cookies::parse_set_cookie("A=1; Expires=not-a-date", "h");
    REQUIRE(u.has_value());
    CHECK(!u->expires.has_value());
}

TEST(gateway_cookie, rejects_malformed_pairs) {
    // Empty name / no '=' / control chars in value / bad name characters.
    CHECK(!gp::cookies::parse_set_cookie("=v", "h").has_value());
    CHECK(!gp::cookies::parse_set_cookie("noequals", "h").has_value());
    CHECK(!gp::cookies::parse_set_cookie("A=v\r\nX: 1", "h").has_value());
    CHECK(!gp::cookies::parse_set_cookie("A B=v", "h").has_value());
    CHECK(!gp::cookies::parse_set_cookie("", "h").has_value());
    // Embedded quote in a quoted value.
    CHECK(!gp::cookies::parse_set_cookie("A=\"b\"c\"", "h").has_value());
}

// ---- End-to-end flows (loopback fixture gateway) ---------------------------

namespace {

const char* kLoginHtml =
    "<html><body>"
    "<form action=\"/sslvpn-login\" method=\"post\">"
    "<input type=\"hidden\" name=\"IKEY\" value=\"SESS-1\">"
    "<input type=\"hidden\" name=\"authType\" value=\"password\">"
    "</form></body></html>";

const char* kPortalHtml =
    "<html><body>"
    "<form action=\"/sslvpn/conn\" method=\"post\">"
    "<input type=\"hidden\" name=\"IKEY\" value=\"SESS-1\">"
    "</form></body></html>";

// Fixture gateway: prelogin -> login (302 + cookie) -> portal -> connect.
// `connect_mode`: "redirect" => POST /sslvpn/conn answers 302 Location;
//                 "form"     => answers 200 with a form naming the endpoint.
void start_fixture_gateway(MultiServer& srv, const std::string& connect_mode) {
    CHECK(srv.start(
        [connect_mode](int cfd, const std::string& raw) {
            auto req = parse_request(raw);
            std::string resp;
            if (req.method == "GET" && req.path.rfind("/sslvpnd/prelogin.xml", 0) == 0) {
                resp = http_response(200, "<prelogin><session_id>SESS-1</session_id></prelogin>",
                                     {{"Set-Cookie", "IKEY=SESS-1; Path=/; HttpOnly"}});
            } else if (req.method == "GET" && req.path.rfind("/sslvpn-login", 0) == 0) {
                resp = http_response(200, kLoginHtml);
            } else if (req.method == "POST" && req.path.rfind("/sslvpn-login", 0) == 0) {
                resp = http_response(302, "",
                                     {{"Location", "/login-ok"},
                                      {"Set-Cookie", "SESSION=abc123; Path=/; HttpOnly"}});
            } else if (req.method == "GET" && req.path.rfind("/login-ok", 0) == 0) {
                resp = http_response(200, "logged in");
            } else if (req.method == "GET" && req.path.rfind("/portal/index.html", 0) == 0) {
                resp = http_response(200, kPortalHtml);
            } else if (req.method == "POST" && req.path.rfind("/sslvpn/conn", 0) == 0) {
                if (connect_mode == "form") {
                    resp = http_response(
                        200,
                        "<html><body><form action=\"/tunnel/alt\" method=\"post\">"
                        "<input type=\"hidden\" name=\"IKEY\" value=\"SESS-1\"></form>"
                        "</body></html>");
                } else {
                    resp = http_response(302, "", {{"Location", "/tunnel/start?proto=dtls"}});
                }
            } else {
                resp = http_response(404, "not found");
            }
            gp::net::send_all(cfd, resp.data(), resp.size());
        },
        12));
}

std::unique_ptr<GatewayClient> make_client(MultiServer& srv, const std::string& dir) {
    SecurityOptions o;
    GatewayConfig cfg;
    cfg.gateway_host = "gw.local";
    cfg.base_url = "http://127.0.0.1:" + std::to_string(srv.port);
    std::string err;
    auto c = GatewayClient::create(o, cfg, dir, &err);
    REQUIRE(c != nullptr);
    return c;
}

}  // namespace

TEST(gateway_flow, full_prelogin_login_connect_extend_redirect_mode) {
    MultiServer srv;
    start_fixture_gateway(srv, "redirect");
    std::string dir = tmp_dir("flow");
    auto client = make_client(srv, dir);

    std::string err;
    CHECK(client->prelogin(&err));
    CHECK_EQ(client->session_id(), std::string("SESS-1"));
    auto ikey = client->store().find("127.0.0.1", "/", "IKEY");
    REQUIRE(ikey.has_value());
    CHECK_EQ(ikey->value, std::string("SESS-1"));

    CHECK(client->login("admin", "p@ss word", &err));
    // The login discovery GET must carry the IKEY cookie from prelogin.
    {
        auto reqs = srv.parsed();
        REQUIRE(reqs.size() >= 2);
        CHECK(reqs[1].header("cookie").find("IKEY=SESS-1") != std::string::npos);
    }
    // SESSION cookie was set on the 302 hop and must be in the jar.
    auto sess = client->store().find("127.0.0.1", "/", "SESSION");
    REQUIRE(sess.has_value());
    CHECK_EQ(sess->value, std::string("abc123"));

    // The credential POST: form fields + username/password, URL-encoded.
    {
        auto reqs = srv.parsed();
        bool found = false;
        for (const auto& r : reqs) {
            if (r.method == "POST" && r.path.rfind("/sslvpn-login", 0) == 0) {
                found = true;
                CHECK(r.body.find("username=admin") != std::string::npos);
                CHECK(r.body.find("password=p%40ss+word") != std::string::npos);
                CHECK(r.body.find("IKEY=SESS-1") != std::string::npos);
                CHECK(r.body.find("authType=password") != std::string::npos);
            }
        }
        REQUIRE(found);
    }

    CHECK(client->connect(&err));
    CHECK_EQ(client->tunnel_endpoint(), std::string("http://127.0.0.1:") +
                                            std::to_string(srv.port) + "/tunnel/start?proto=dtls");

    // Portal GET carries both cookies and the IKEY query parameter.
    {
        auto reqs = srv.parsed();
        bool found = false;
        for (const auto& r : reqs) {
            if (r.method == "GET" && r.path.rfind("/portal/index.html", 0) == 0) {
                found = true;
                CHECK(r.path.find("IKEY=SESS-1") != std::string::npos);
                CHECK(r.header("cookie").find("SESSION=abc123") != std::string::npos);
            }
        }
        REQUIRE(found);
    }

    CHECK(client->extend_session(&err));
    {
        auto reqs = srv.parsed();
        int posts = 0;
        for (const auto& r : reqs) {
            if (r.method == "POST" && r.path.rfind("/sslvpn/conn", 0) == 0) {
                ++posts;
                CHECK(r.body.find("IKEY=SESS-1") != std::string::npos);
            }
        }
        CHECK_EQ(posts, 2);  // connect + extend
    }
}

TEST(gateway_flow, connect_endpoint_from_form_body) {
    MultiServer srv;
    start_fixture_gateway(srv, "form");
    std::string dir = tmp_dir("flowform");
    auto client = make_client(srv, dir);

    std::string err;
    CHECK(client->prelogin(&err));
    CHECK(client->login("admin", "pw", &err));
    CHECK(client->connect(&err));
    CHECK_EQ(client->tunnel_endpoint(),
             std::string("http://127.0.0.1:") + std::to_string(srv.port) + "/tunnel/alt");
}

// ---- Fail-closed behavior --------------------------------------------------

TEST(gateway_fail, prelogin_rejects_dtd_and_bad_status) {
    // DOCTYPE => XXE vector: must be rejected by the strict XML parser.
    MultiServer srv;
    CHECK(srv.start(
        [](int cfd, const std::string&) {
            std::string resp =
                http_response(200,
                              "<?xml version=\"1.0\"?>\n"
                              "<!DOCTYPE prelogin [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>\n"
                              "<prelogin><session_id>&xxe;</session_id></prelogin>");
            gp::net::send_all(cfd, resp.data(), resp.size());
        },
        1));

    std::string dir = tmp_dir("fail1");
    auto client = make_client(srv, dir);
    std::string err;
    CHECK(!client->prelogin(&err));
    CHECK(err.find("XML") != std::string::npos);

    // Non-200 status: fail closed.
    MultiServer srv2;
    CHECK(srv2.start(
        [](int cfd, const std::string&) {
            std::string resp = http_response(500, "boom");
            gp::net::send_all(cfd, resp.data(), resp.size());
        },
        1));
    auto client2 = make_client(srv2, tmp_dir("fail2"));
    err.clear();
    CHECK(!client2->prelogin(&err));
    CHECK(err.find("500") != std::string::npos);
}

TEST(gateway_fail, login_refuses_foreign_redirect_and_hides_credentials) {
    MultiServer srv;
    CHECK(srv.start(
        [](int cfd, const std::string& raw) {
            auto req = parse_request(raw);
            std::string resp;
            if (req.method == "GET" && req.path.rfind("/sslvpn-login", 0) == 0) {
                resp = http_response(200, kLoginHtml);
            } else if (req.method == "POST") {
                // Attack: bounce the client (and its cookies) to a foreign host.
                resp = http_response(302, "", {{"Location", "https://evil.example/steal"}});
            } else {
                resp = http_response(401, "");
            }
            gp::net::send_all(cfd, resp.data(), resp.size());
        },
        4));

    auto client = make_client(srv, tmp_dir("fail3"));
    std::string err;
    CHECK(client->prelogin(&err) || true);  // prelogin may 404 here; irrelevant
    CHECK(!client->login("admin", "s3cret-password", &err));
    CHECK(err.find("foreign origin") != std::string::npos);
    // The error must never contain the credentials.
    CHECK(err.find("s3cret-password") == std::string::npos);
    CHECK(err.find("admin") == std::string::npos);
}

TEST(gateway_fail, login_401_error_is_generic) {
    MultiServer srv;
    CHECK(srv.start(
        [](int cfd, const std::string& raw) {
            auto req = parse_request(raw);
            std::string resp;
            if (req.method == "GET" && req.path.rfind("/sslvpn-login", 0) == 0) {
                resp = http_response(200, kLoginHtml);
            } else if (req.method == "POST") {
                resp = http_response(401, "wrong username or password: admin");
            } else {
                resp = http_response(404, "");
            }
            gp::net::send_all(cfd, resp.data(), resp.size());
        },
        3));

    auto client = make_client(srv, tmp_dir("fail4"));
    std::string err;
    CHECK(!client->login("admin", "hunter2", &err));
    CHECK(err.find("401") != std::string::npos);
    CHECK(err.find("hunter2") == std::string::npos);
    // The (attacker-controlled) response body must not leak into the error.
    CHECK(err.find("wrong username") == std::string::npos);
}

TEST(gateway_fail, connect_requires_prelogin_and_extend_requires_connect) {
    MultiServer srv;
    CHECK(srv.start(
        [](int cfd, const std::string&) {
            std::string resp = http_response(200, "x");
            gp::net::send_all(cfd, resp.data(), resp.size());
        },
        2));

    auto client = make_client(srv, tmp_dir("fail5"));
    std::string err;
    CHECK(!client->connect(&err));
    CHECK(err.find("prelogin") != std::string::npos);
    err.clear();
    CHECK(!client->extend_session(&err));
    CHECK(err.find("connect") != std::string::npos);
}

TEST(gateway_fail, create_validates_config) {
    SecurityOptions o;
    GatewayConfig cfg;
    cfg.gateway_host = "gw.local";
    cfg.base_url = "https://gw.local/";  // trailing slash
    std::string err;
    CHECK(GatewayClient::create(o, cfg, tmp_dir("fail6"), &err) == nullptr);
    CHECK(!err.empty());

    cfg.base_url = "ftp://gw.local";
    CHECK(GatewayClient::create(o, cfg, tmp_dir("fail7"), &err) == nullptr);

    GatewayConfig empty_host;
    empty_host.base_url = "https://gw.local";
    CHECK(GatewayClient::create(o, empty_host, tmp_dir("fail8"), &err) == nullptr);
}

int main() {
    return gp::test::Registry::instance().run_all();
}