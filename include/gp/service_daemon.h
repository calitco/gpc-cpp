// Local service daemon — port of the Rust gpservice (apps/gpservice)
// security-relevant surface: loopback-only TCP listener, /health endpoint,
// WebSocket upgrade with AEAD (ChaCha20-Poly1305) message payloads, and a
// 0600 lock file carrying pid:port.
//
// Hardened vs the original:
//  - the lock file is written 0600 and mode-verified (L-2: the Rust version
//    used default-umask creation → world-readable);
//  - loopback-only bind by construction (no opt-in to other binds here);
//  - concurrent-connection cap and per-connection lifetime cap (slowloris /
//    resource-exhaustion protection, same pattern as AuthServer);
//  - every WS message is authenticated+encrypted; malformed or failed-decrypt
//    input ends the session with a Close frame, never a crash.
//
// Out of scope (as in the C++ core): the actual GUI install action and the
// tunnel data plane. The daemon acknowledges those commands but performs no
// side effects beyond logging them to its stdout.
#pragma once

#include <atomic>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "gp/service_key.h"

namespace gp::net {
class TcpListener;
}  // namespace gp::net

namespace gp::service {

struct DaemonConfig {
    std::string dir;                     // must exist; holds gpservice.lock (0600)
    int port = 0;                        // 0 = ephemeral
    ServiceKey key{};                    // AEAD key: generate() or permission-checked load
    size_t max_message_bytes = 1 << 20;  // per decrypted WS message
    int max_connections = 8;             // concurrent connection cap
    int conn_lifetime_ms = 300000;       // per-connection lifetime cap
};

class ServiceDaemon {
   public:
    // Bind, write the lock file, and start the accept loop. Returns nullptr
    // (with *err) on any failure; nothing is left listening in that case.
    static std::unique_ptr<ServiceDaemon> start(const DaemonConfig& cfg,
                                                std::string* err = nullptr);
    ~ServiceDaemon();
    ServiceDaemon(const ServiceDaemon&) = delete;
    ServiceDaemon& operator=(const ServiceDaemon&) = delete;

    // Idempotent: stop accepting, wait for in-flight connections (bounded by
    // their lifetime cap), remove the lock file.
    void stop();

    int port() const { return port_; }
    pid_t pid() const;

   private:
    ServiceDaemon();
    void accept_loop();
    void handle_conn(int fd);
    bool ws_session(int fd, const std::string& ws_key);
    // Dispatch one decrypted JSON command; returns the JSON reply.
    std::string dispatch(const std::string& plaintext) const;

    DaemonConfig cfg_;
    int port_ = 0;
    std::string lock_path_;
    // unique_ptr so the header can keep TcpListener (src/net_common.h) out of
    // the public include surface; the destructor is defined in the .cpp where
    // the type is complete.
    std::unique_ptr<gp::net::TcpListener> listener_;
    std::atomic<bool> stopping_{false};
    std::atomic<int> active_{0};
    std::thread acceptor_;
    std::mutex threads_mu_;
    std::vector<std::unique_ptr<std::thread>> handlers_;
};

}  // namespace gp::service