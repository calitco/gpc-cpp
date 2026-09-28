// Optional debug tracing — see src/trace.cpp for the implementation.
//
// gpclient --verbose installs a sink so the whole process can be followed:
// posture -> prelogin -> login -> connect -> tunnel -> session renewals,
// including every HTTP hop (method, path, status, byte count) and every
// certificate decision.
//
// Contract (M-3): trace lines carry METADATA ONLY — stage names, URL paths,
// HTTP status codes, byte counts, log-safe reasons. Never credentials,
// cookie values, query strings carrying session tokens, request/response
// bodies, or callback payloads. Callers must not pass such values to
// GP_TRACE; the tests in test_client_flow.cpp enforce this for the main
// flows.
//
// Off by default: with no sink installed emit() is a single atomic load, so
// instrumented code costs nothing in normal operation. There is no other
// global state (no buffering, no formatting cache); the sink is process-wide
// and thread-safe.
#pragma once

#include <functional>
#include <sstream>
#include <string>

namespace gp::trace {

using Sink = std::function<void(const std::string& line)>;

// Install the process-wide sink (nullptr disables tracing). Thread-safe.
void set_sink(Sink sink);

// True when a sink is installed.
bool enabled();

// Deliver one line to the sink; a no-op when disabled. The line must not
// contain a newline.
void emit(const std::string& line);

// Concatenate arguments into one trace line (printf-style fragments: the
// caller owns all spacing — "http: GET ", "/x", " -> HTTP ", 200 becomes
// "http: GET /x -> HTTP 200"). A single string argument is returned as-is.
inline std::string format(const std::string& first) {
    return first;
}
template <class T>
std::string format(const T& first) {
    std::ostringstream oss;
    oss << first;
    return oss.str();
}
template <class T, class... Rest>
std::string format(const T& first, const Rest&... rest) {
    std::string head;
    {
        std::ostringstream oss;
        oss << first;
        head = oss.str();
    }
    return head + format(rest...);
}

}  // namespace gp::trace

// Trace one line if a sink is installed. Metadata only — see the contract
// above; never pass secrets through here.
#define GP_TRACE(...) ::gp::trace::emit(::gp::trace::format(__VA_ARGS__))