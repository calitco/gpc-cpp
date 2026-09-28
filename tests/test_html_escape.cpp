#include <gp/html_escape.h>

#include "test_framework.h"

using namespace gp::html;

TEST(html, escapes_all_special_characters) {
    CHECK_EQ(escape_text("<script>alert(1)</script>"),
             std::string("&lt;script&gt;alert(1)&lt;/script&gt;"));
    CHECK_EQ(escape_text("a&b\"c'd"), std::string("a&amp;b&quot;c&#39;d"));
    CHECK_EQ(escape_text("plain text 123"), std::string("plain text 123"));
}

TEST(html, accepts_valid_redirect_targets) {
    CHECK(valid_redirect_target("https://portal.example.com/sso", {}));
    CHECK(valid_redirect_target("http://localhost:8443/next", {}));
    CHECK(valid_redirect_target("https://sub.portal.example.com/a/b?c=d#e", {}));
}

TEST(html, rejects_invalid_redirect_targets) {
    // Wrong / missing scheme.
    CHECK(!valid_redirect_target("javascript:alert(1)", {}));
    CHECK(!valid_redirect_target("file:///etc/passwd", {}));
    CHECK(!valid_redirect_target("portal.example.com/path", {}));
    CHECK(!valid_redirect_target("", {}));
    // CRLF / control characters (header injection).
    CHECK(!valid_redirect_target("https://x.com/\r\nX-Injected: 1", {}));
    CHECK(!valid_redirect_target("https://x.com/\nEvil", {}));
    CHECK(!valid_redirect_target(std::string("https://x.com/") + "\x01" + "bad", {}));
    // Userinfo (credential smuggling).
    CHECK(!valid_redirect_target("https://user:pass@x.com/", {}));
    // Empty host.
    CHECK(!valid_redirect_target("https:///path", {}));
}

TEST(html, redirect_allowlist) {
    std::vector<std::string> allow{"portal.example.com"};
    CHECK(valid_redirect_target("https://portal.example.com/x", allow));
    CHECK(valid_redirect_target("https://Portal.Example.com:8443/x", allow));
    CHECK(!valid_redirect_target("https://evil.example.com/x", allow));
    CHECK(!valid_redirect_target("https://notportal.example.com/x", allow));
}

int main() {
    return gp::test::Registry::instance().run_all();
}
