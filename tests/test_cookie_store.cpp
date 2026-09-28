// Tests for gp::cookies — cookie persistence with 0700/0600 enforcement,
// RFC 6265-style matching, and fail-closed behavior.
#include <sys/stat.h>
#include <unistd.h>

#include <cstdio>

#include "gp/cookie_store.h"
#include "test_framework.h"

using gp::cookies::Cookie;
using gp::cookies::Store;

namespace {

std::string tmp_dir() {
    char tmpl[] = "/tmp/gp_cookie_test_XXXXXX";
    char* d = mkdtemp(tmpl);
    REQUIRE(d != nullptr);
    return d;
}

void rm_rf(const std::string& dir) {
    ::system(("rm -rf " + dir).c_str());
}

mode_t mode_of(const std::string& p) {
    struct stat st{};
    REQUIRE(stat(p.c_str(), &st) == 0);
    return st.st_mode & 0777;
}

Cookie make_cookie(const std::string& name, const std::string& domain,
                   const std::string& value = "v") {
    Cookie c;
    c.name = name;
    c.domain = domain;
    c.value = value;
    return c;
}

}  // namespace

TEST(cookie_store, open_creates_0700_dir_and_0600_file_under_umask_0) {
    mode_t old = umask(0);  // worst case: everything created world-readable
    std::string dir = tmp_dir();
    rm_rf(dir + "/sub");
    Store s = Store::open(dir + "/sub", nullptr);
    CHECK(s.ok());
    CHECK_EQ(mode_of(dir + "/sub"), (mode_t)0700);
    Cookie c = make_cookie("a", "example.com");
    CHECK(s.set(c, nullptr));
    CHECK_EQ(mode_of(dir + "/sub/cookies.txt"), (mode_t)0600);
    umask(old);
    rm_rf(dir);
}

TEST(cookie_store, set_find_roundtrip_and_upsert) {
    std::string dir = tmp_dir();
    Store s = Store::open(dir, nullptr);
    CHECK(s.ok());
    Cookie c = make_cookie("sid", "portal.example.com", "abc123");
    c.path = "/portal";
    CHECK(s.set(c, nullptr));
    auto got = s.find("portal.example.com", "/portal", "sid");
    REQUIRE(got.has_value());
    CHECK_EQ(got->value, std::string("abc123"));
    CHECK_EQ(s.size(), (size_t)1);

    // Upsert: same (domain, path, name) replaces the value, size unchanged.
    Cookie c2 = c;
    c2.value = "rotated";
    CHECK(s.set(c2, nullptr));
    CHECK_EQ(s.size(), (size_t)1);
    auto got2 = s.find("portal.example.com", "/portal", "sid");
    REQUIRE(got2.has_value());
    CHECK_EQ(got2->value, std::string("rotated"));
    rm_rf(dir);
}

TEST(cookie_store, for_request_domain_matching) {
    std::string dir = tmp_dir();
    Store s = Store::open(dir, nullptr);
    CHECK(s.ok());

    Cookie domain_cookie = make_cookie("dc", "example.com", "dv");
    domain_cookie.host_only = false;  // explicit Domain= example.com
    CHECK(s.set(domain_cookie, nullptr));

    Cookie host_only = make_cookie("ho", "api.example.com", "hv");
    host_only.host_only = true;  // derived from request host
    CHECK(s.set(host_only, nullptr));

    // Domain cookie: exact + subdomain match, no suffix-attack match.
    auto v = s.for_request("example.com", true);
    CHECK_EQ(v.size(), (size_t)1);
    CHECK_EQ(v[0].name, std::string("dc"));
    v = s.for_request("api.example.com", true);
    CHECK_EQ(v.size(), (size_t)2);  // dc + ho
    v = s.for_request("notexample.com", true);
    CHECK_EQ(v.size(), (size_t)0);
    v = s.for_request("example.com.evil.com", true);
    CHECK_EQ(v.size(), (size_t)0);

    // Host-only cookie: exact host only, NOT sibling subdomains.
    v = s.for_request("other.example.com", true);
    CHECK_EQ(v.size(), (size_t)1);
    CHECK_EQ(v[0].name, std::string("dc"));
    rm_rf(dir);
}
TEST(cookie_store, for_request_path_matching) {
    std::string dir = tmp_dir();
    Store s = Store::open(dir, nullptr);
    CHECK(s.ok());
    Cookie c = make_cookie("p", "example.com");
    c.path = "/portal";
    CHECK(s.set(c, nullptr));

    auto v = s.for_request("example.com", true, "/portal");
    CHECK_EQ(v.size(), (size_t)1);
    v = s.for_request("example.com", true, "/portal/login");
    CHECK_EQ(v.size(), (size_t)1);
    v = s.for_request("example.com", true, "/application");  // prefix trap
    CHECK_EQ(v.size(), (size_t)0);
    rm_rf(dir);
}

TEST(cookie_store, for_request_secure_and_expiry) {
    std::string dir = tmp_dir();
    Store s = Store::open(dir, nullptr);
    CHECK(s.ok());

    Cookie sec = make_cookie("sec", "example.com");
    sec.secure = true;
    CHECK(s.set(sec, nullptr));

    Cookie expired = make_cookie("old", "example.com");
    expired.expires = gp::cookies::epoch() + std::chrono::hours(-1);
    CHECK(s.set(expired, nullptr));

    Cookie session = make_cookie("sess", "example.com");  // no expiry
    CHECK(s.set(session, nullptr));

    auto v = s.for_request("example.com", false);
    CHECK_EQ(v.size(), (size_t)1);
    CHECK_EQ(v[0].name, std::string("sess"));  // secure blocked on http, expired pruned
    v = s.for_request("example.com", true);
    CHECK_EQ(v.size(), (size_t)2);  // sec + sess
    rm_rf(dir);
}

TEST(cookie_store, remove_works) {
    std::string dir = tmp_dir();
    Store s = Store::open(dir, nullptr);
    CHECK(s.ok());
    CHECK(s.set(make_cookie("a", "example.com"), nullptr));
    CHECK(s.set(make_cookie("b", "example.com"), nullptr));
    CHECK(s.remove("example.com", "a"));
    CHECK(!s.remove("example.com", "a"));  // already gone
    CHECK_EQ(s.size(), (size_t)1);
    auto v = s.for_request("example.com", true);
    CHECK_EQ(v[0].name, std::string("b"));
    rm_rf(dir);
}

TEST(cookie_store, load_existing_file_skips_malformed) {
    std::string dir = tmp_dir();
    Store s = Store::open(dir, nullptr);
    CHECK(s.ok());
    // Fixture: comment + 2 valid lines + 1 malformed (5 fields).
    FILE* f = fopen((dir + "/cookies.txt").c_str(), "w");
    REQUIRE(f != nullptr);
    fprintf(f, "# comment\n");
    fprintf(f, ".example.com\t1\t/\t0\t0\tsid\ttok123\n");  // domain cookie
    fprintf(f, "badline\t1\t/\t0\n");                       // malformed
    fprintf(f, "api.example.com\t0\t/portal\t1\t9999999999\tsecure_cookie\tv2\n");
    fclose(f);

    Store s2 = Store::open(dir, nullptr);
    CHECK(s2.ok());
    CHECK_EQ(s2.skipped_lines(), (size_t)1);
    CHECK_EQ(s2.size(), (size_t)2);
    auto c = s2.find("example.com", "/", "sid");
    REQUIRE(c.has_value());
    CHECK(!c->host_only);            // flag "1" => subdomains included
    CHECK(!c->expires.has_value());  // 0 => session cookie
    auto sc = s2.find("api.example.com", "/portal", "secure_cookie");
    REQUIRE(sc.has_value());
    CHECK(sc->secure);
    CHECK(sc->host_only);
    rm_rf(dir);
}

TEST(cookie_store, rejects_tab_or_newline_in_value) {
    std::string dir = tmp_dir();
    Store s = Store::open(dir, nullptr);
    CHECK(s.ok());
    Cookie c = make_cookie("evil", "example.com", "a\tb");
    std::string err;
    CHECK(!s.set(c, &err));
    CHECK_EQ(s.size(), (size_t)0);
    c.value = "x\ny";
    CHECK(!s.set(c, &err));
    c.value = "ok";
    CHECK(s.set(c, nullptr));
    rm_rf(dir);
}

TEST(cookie_store, save_reenforces_0600_after_external_chmod) {
    std::string dir = tmp_dir();
    Store s = Store::open(dir, nullptr);
    CHECK(s.ok());
    CHECK(s.set(make_cookie("a", "example.com"), nullptr));
    // Simulate drift: someone chmods the jar world-readable.
    REQUIRE(chmod((dir + "/cookies.txt").c_str(), 0644) == 0);
    CHECK_EQ(mode_of(dir + "/cookies.txt"), (mode_t)0644);
    // Any subsequent mutation must restore 0600 via the atomic rewrite.
    CHECK(s.set(make_cookie("b", "example.com"), nullptr));
    CHECK_EQ(mode_of(dir + "/cookies.txt"), (mode_t)0600);
    rm_rf(dir);
}

int main() {
    return gp::test::Registry::instance().run_all();
}