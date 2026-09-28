// One-shot, token-authenticated callback receiver — the C++ replacement for
// browser_auth.rs wait_auth_data() (finding H-1).
//
// Fixes:
//  - per-session random token in the URL path; connections to any other path
//    are rejected (no more unauthenticated local session injection);
//  - hard payload size cap (413 + close on overflow, no unbounded read);
//  - overall deadline so a silent connection cannot hang auth forever;
//  - port file written 0600 (was fine before, kept and asserted in tests).
#pragma once

#include <chrono>
#include <cstdint>
#include <memory>
#include <string>

#include "gp/security_options.h"

namespace gp::auth {

struct CallbackResult {
    enum class Status {
        Delivered,         // token matched, payload captured (one-shot consumed)
        BadToken,          // wrong path/token — connection rejected
        TooLarge,          // payload exceeded the cap — connection rejected
        Timeout,           // deadline reached with no valid delivery
        AlreadyDelivered,  // wait called after the one-shot was consumed
        Error,             // socket/IO error
    };
    Status status = Status::Error;
    std::string payload;  // only set when Delivered
    std::string reason;   // always safe to log (never contains the payload)
};

class CallbackListener {
   public:
    explicit CallbackListener(const SecurityOptions& opts);
    ~CallbackListener();

    // Bind 127.0.0.1:<ephemeral> and write the port file (0600).
    bool start(std::string* err = nullptr);

    uint16_t port() const;
    const std::string& token() const;
    // URL path the browser must visit: "/<token>"
    std::string url_path() const;
    const std::string& port_file() const;

    // Block until a valid delivery, timeout, or rejection. One-shot: after a
    // Delivered result the listener is closed and further calls return
    // AlreadyDelivered.
    CallbackResult wait_for_callback();

    void stop();

   private:
    void worker_loop();
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace gp::auth
