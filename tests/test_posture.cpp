// Tests for gp::posture — argv-vector spawn (no shell), deadline kill,
// output caps, exec-failure detection, key=value parsing.
#include <cstdio>

#include "gp/posture.h"
#include "test_framework.h"

using gp::posture::CheckConfig;
using gp::posture::CheckResult;

TEST(posture, captures_stdout_and_exit_code) {
    CheckConfig cfg;
    cfg.program = "/bin/echo";
    cfg.args = {"hello=world"};
    CheckResult r = gp::posture::run_check(cfg);
    CHECK(r.ok);
    CHECK(!r.spawn_failed);
    CHECK_EQ(r.exit_code, 0);
    CHECK_EQ(r.stdout_text, std::string("hello=world\n"));
}

TEST(posture, nonzero_exit_reported_but_ok) {
    CheckConfig cfg;
    cfg.program = "/bin/false";
    CheckResult r = gp::posture::run_check(cfg);
    CHECK(r.ok);  // ran to completion
    CHECK_EQ(r.exit_code, 1);
}

TEST(posture, timeout_kills_child) {
    CheckConfig cfg;
    cfg.program = "/bin/sleep";
    cfg.args = {"5"};
    cfg.timeout_ms = 300;
    CheckResult r = gp::posture::run_check(cfg);
    CHECK(r.timed_out);
    CHECK(!r.ok);
    CHECK_EQ(r.exit_code, 128 + 9);  // SIGKILL
}

TEST(posture, output_capped_per_stream) {
    const char* path = "/tmp/gp_posture_big.txt";
    FILE* f = fopen(path, "w");
    REQUIRE(f != nullptr);
    for (int i = 0; i < 8192; ++i)
        fputc('x', f);
    fclose(f);

    CheckConfig cfg;
    cfg.program = "/bin/cat";
    cfg.args = {path};
    cfg.max_output_bytes = 1024;
    CheckResult r = gp::posture::run_check(cfg);
    CHECK(r.ok);
    CHECK_EQ(r.stdout_text.size(), (size_t)1024);
    remove(path);
}

TEST(posture, stderr_captured) {
    CheckConfig cfg;
    cfg.program = "/bin/sh";
    cfg.args = {"-c", "echo oops >&2"};  // test harness only: run_check itself never shells out
    CheckResult r = gp::posture::run_check(cfg);
    CHECK(r.ok);
    CHECK(r.stderr_text.find("oops") != std::string::npos);
}

TEST(posture, missing_program_reports_spawn_failure) {
    CheckConfig cfg;
    cfg.program = "/nonexistent/hipreport-xyz";
    CheckResult r = gp::posture::run_check(cfg);
    CHECK(r.spawn_failed);
    CHECK(!r.ok);
    CHECK_EQ(r.exit_code, 127);
}

TEST(posture, parse_key_value_parses_lines) {
    const std::string text =
        "gateway=gp.example.com\n"
        "  os   = Linux x86_64\n"
        "no_equals_line\n"
        "=missingkey\n"
        "url=https://host/path?a=1&b=2";
    auto m = gp::posture::parse_key_value(text);
    CHECK_EQ(m.size(), (size_t)3);
    CHECK_EQ(m["gateway"], std::string("gp.example.com"));
    CHECK_EQ(m["os"], std::string(" Linux x86_64"));  // value keeps everything after first '='
    CHECK_EQ(m["url"], std::string("https://host/path?a=1&b=2"));
}

int main() {
    return gp::test::Registry::instance().run_all();
}