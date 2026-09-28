// GUI launch layer — port of the Rust `launch-gui` seam. The real Tauri
// webview cannot be rendered here (no display, and Tauri is a Rust framework),
// so this module ports what matters security-wise: the LAUNCH PROTOCOL.
//
//  - The auth URL (which embeds the one-time callback token) is passed to the
//    child over STDIN — one line, then EOF — NEVER via argv. This fixes H-3
//    by construction for any GUI host that reads its URL from stdin (the
//    Rust Tauri app already did this with --read-secrets-on-stdin).
//  - Hard deadline: a hung webview is killed after timeout_ms instead of
//    blocking the client forever.
//  - stdout capture is capped; stderr is inherited so GUI logs reach the
//    operator's terminal (they are not secret material).
//
// Child protocol: read one line from stdin (the URL), open it, exit 0 on
// success / non-zero on failure.
#pragma once

#include <cstddef>
#include <string>
#include <vector>

namespace gp::gui {

struct GuiConfig {
    std::string program;            // GUI host binary (Tauri app, webview wrapper, ...)
    std::vector<std::string> args;  // static args only — never the URL
    int timeout_ms = 30000;
    size_t max_stdout_bytes = 1 << 20;
};

struct GuiResult {
    bool completed = false;  // child exited (any code) within the deadline
    bool timed_out = false;
    bool spawn_failed = false;
    int exit_code = -1;
    std::string stdout_text;  // capped at max_stdout_bytes
};

// Launch the GUI with `url` delivered on stdin. The URL never appears in the
// child's argv (verifiable via /proc/<pid>/cmdline).
GuiResult launch(const GuiConfig& cfg, const std::string& url);

}  // namespace gp::gui