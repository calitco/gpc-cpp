// HIP/CSC posture check execution — port of the Rust hip.rs/csc.rs command
// spawn logic. The actual GlobalProtect `hipreport`/`csc` binaries are
// proprietary and not shipped here; what IS ported (and testable) is the
// execution layer, which carries the security properties:
//  - argv-vector exec only: NO shell is ever involved, so gateway URLs or
//    any other inputs cannot inject commands (the Rust code used command
//    spawning with explicit args — same property, preserved);
//  - hard deadline: the child is SIGKILLed if it exceeds timeout_ms;
//  - output capture is capped at max_output_bytes per stream (a runaway or
//    hostile binary cannot exhaust memory);
//  - spawn/exec failures are reported distinctly from non-zero exits.
#pragma once

#include <cstddef>
#include <map>
#include <string>
#include <vector>

namespace gp::posture {

struct CheckConfig {
    std::string program;            // resolved via PATH (execvp) if not absolute
    std::vector<std::string> args;  // explicit argv after the program name
    int timeout_ms = 30000;
    size_t max_output_bytes = 1 << 20;  // per stream
};

struct CheckResult {
    bool ok = false;         // spawned, ran to completion within caps/timeout
    int exit_code = -1;      // -1 when the process could not be reaped normally
    bool timed_out = false;  // killed at the deadline
    bool spawn_failed = false;
    std::string stdout_text;  // truncated to max_output_bytes
    std::string stderr_text;  // truncated to max_output_bytes
};

// Run one posture check. Never invokes a shell. On timeout the child is
// killed and reaped; timed_out is set and ok is false.
CheckResult run_check(const CheckConfig& cfg);

// Parse "key=value" lines (GlobalProtect posture tools emit key/value style
// summaries). Lines without '=' are skipped; values keep everything after
// the FIRST '='; surrounding whitespace on keys is trimmed.
std::map<std::string, std::string> parse_key_value(const std::string& text);

}  // namespace gp::posture