// Tests for gp::gui — URL-via-stdin launch protocol (H-3 fix), deadline kill.
#include "gp/gui.h"
#include "test_framework.h"

using gp::gui::GuiConfig;
using gp::gui::GuiResult;

namespace {
const std::string kUrl = "https://127.0.0.1:8443/callback?token=abc123";
}  // namespace

TEST(gui, url_delivered_via_stdin) {
    GuiConfig cfg;
    cfg.program = "/bin/cat";  // echoes stdin back: proves delivery
    GuiResult r = gp::gui::launch(cfg, kUrl);
    CHECK(r.completed);
    CHECK(!r.timed_out);
    CHECK_EQ(r.exit_code, 0);
    CHECK_EQ(r.stdout_text, kUrl + "\n");
}

TEST(gui, url_never_in_argv) {
    // Child prints its own argv. If the URL leaked into arguments it would show
    // up here; it must not (the URL travels on stdin only).
    GuiConfig cfg;
    cfg.program = "/bin/sh";
    cfg.args = {"-c", "printf '%s\\n' \"$@\""};
    GuiResult r = gp::gui::launch(cfg, kUrl);
    CHECK(r.completed);
    CHECK_EQ(r.exit_code, 0);
    CHECK(r.stdout_text.find("token=abc123") == std::string::npos);
}

TEST(gui, timeout_kills_hung_gui) {
    GuiConfig cfg;
    cfg.program = "/bin/sleep";
    cfg.args = {"5"};
    cfg.timeout_ms = 300;
    GuiResult r = gp::gui::launch(cfg, kUrl);
    CHECK(r.timed_out);
    CHECK(!r.completed);
    CHECK_EQ(r.exit_code, 128 + 9);
}

TEST(gui, nonzero_exit_reported) {
    GuiConfig cfg;
    cfg.program = "/bin/sh";
    cfg.args = {"-c", "read u; exit 3"};
    GuiResult r = gp::gui::launch(cfg, kUrl);
    CHECK(r.completed);
    CHECK_EQ(r.exit_code, 3);
}

TEST(gui, missing_program_reports_spawn_failure) {
    GuiConfig cfg;
    cfg.program = "/nonexistent/gui-host";
    GuiResult r = gp::gui::launch(cfg, kUrl);
    CHECK(r.spawn_failed);
    CHECK(!r.completed);
}

int main() {
    return gp::test::Registry::instance().run_all();
}