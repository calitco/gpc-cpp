// Process-wide trace sink — see include/gp/trace.h for the contract.
#include "gp/trace.h"

#include <atomic>
#include <mutex>

namespace gp::trace {

namespace {
std::mutex g_mu;
Sink g_sink;
std::atomic<bool> g_enabled{false};
}  // namespace

void set_sink(Sink sink) {
    {
        std::lock_guard<std::mutex> lk(g_mu);
        g_sink = std::move(sink);
    }
    g_enabled.store(static_cast<bool>(g_sink), std::memory_order_release);
}

bool enabled() {
    return g_enabled.load(std::memory_order_acquire);
}

void emit(const std::string& line) {
    // Fast path: one atomic load when tracing is off.
    if (!g_enabled.load(std::memory_order_acquire))
        return;
    Sink local;
    {
        std::lock_guard<std::mutex> lk(g_mu);
        local = g_sink;
    }
    if (local)
        local(line);
}

}  // namespace gp::trace