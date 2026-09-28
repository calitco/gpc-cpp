#include "gp/callback_listener.h"

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <atomic>
#include <condition_variable>
#include <cstdlib>
#include <mutex>
#include <sstream>
#include <thread>

#include "gp/random.h"
#include "gp/trace.h"
#include "net_common.h"

namespace gp::auth {

struct CallbackListener::Impl {
    const SecurityOptions& opts;
    net::TcpListener listener;
    std::string token;
    uint16_t port = 0;
    std::string port_file;
    std::atomic<bool> stopped{false};
    std::thread worker;
    std::mutex m;
    std::condition_variable cv;
    bool done = false;
    bool waited = false;  // wait_for_callback() already returned the result
    CallbackResult result;

    explicit Impl(const SecurityOptions& o) : opts(o) {}

    void finish(CallbackResult r) {
        // Reasons are log-safe: byte counts and rejection tallies, never the
        // payload itself (M-3).
        GP_TRACE("callback: ", r.reason);
        {
            std::lock_guard<std::mutex> lk(m);
            result = std::move(r);
            done = true;
        }
        cv.notify_all();
        stop_locked();
    }

    void stop_locked() {
        stopped.store(true);
        listener.close_fd();
    }
};

CallbackListener::CallbackListener(const SecurityOptions& opts)
    : impl_(std::make_unique<Impl>(opts)) {}

CallbackListener::~CallbackListener() {
    stop();
}

uint16_t CallbackListener::port() const {
    return impl_->port;
}
const std::string& CallbackListener::token() const {
    return impl_->token;
}
std::string CallbackListener::url_path() const {
    return "/" + impl_->token;
}
const std::string& CallbackListener::port_file() const {
    return impl_->port_file;
}

bool CallbackListener::start(std::string* err) {
    auto& im = *impl_;
    im.token = rand::to_base64url(rand::random_bytes(32));  // 256-bit token
    if (!im.listener.bind_to("127.0.0.1", 0)) {
        if (err)
            *err = "cannot bind callback listener to 127.0.0.1";
        return false;
    }
    im.port = im.listener.port();

    // Unique, 0600 port file (same-user readable at most). The token is NOT in
    // this file: a same-user process that reads the port still cannot inject
    // without the token.
    const char* tmpdir = std::getenv("TMPDIR");
    std::string dir = (tmpdir && *tmpdir) ? tmpdir : "/tmp";
    im.port_file =
        dir + "/gp_callback_port." + std::to_string(::getpid()) + "." + im.token.substr(0, 8);
    int fd = ::open(im.port_file.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) {
        if (err)
            *err = "cannot create port file";
        return false;
    }
    // fchmod defeats a permissive umask.
    ::fchmod(fd, 0600);
    std::string content = std::to_string(im.port);
    ssize_t n = ::write(fd, content.data(), content.size());
    ::close(fd);
    if (n != static_cast<ssize_t>(content.size())) {
        if (err)
            *err = "short write to port file";
        return false;
    }

    im.worker = std::thread([this] { worker_loop(); });
    GP_TRACE("callback: listener on 127.0.0.1:", im.port, " (one-shot path hidden)");
    return true;
}

void CallbackListener::worker_loop() {
    auto& im = *impl_;
    auto deadline = std::chrono::steady_clock::now() + im.opts.callback_timeout;
    const std::string want_path = "/" + im.token;
    int rejected_connections = 0;

    while (!im.stopped.load()) {
        auto now = std::chrono::steady_clock::now();
        if (now >= deadline) {
            CallbackResult r;
            r.status = CallbackResult::Status::Timeout;
            r.reason = "deadline reached without valid delivery (" +
                       std::to_string(rejected_connections) + " rejected connection(s))";
            im.finish(std::move(r));
            return;
        }
        // Accept in short slices: closing the listener fd does not interrupt a
        // blocking poll(), so stop() would otherwise wait for the full remaining
        // timeout before the worker notices. 100ms keeps shutdown prompt without
        // spinning.
        int cfd = -1;
        while (!im.stopped.load()) {
            auto now2 = std::chrono::steady_clock::now();
            if (now2 >= deadline)
                break;
            int remaining_ms = static_cast<int>(
                std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now2).count());
            int slice_ms = remaining_ms < 100 ? remaining_ms : 100;
            cfd = im.listener.accept_with_timeout(slice_ms);
            if (cfd >= 0)
                break;
        }
        if (im.stopped.load())
            return;
        if (cfd < 0)
            continue;  // deadline reached: top-of-loop check reports it
        net::set_recv_timeout(cfd, 5000);

        net::ParsedRequest req;
        if (!net::parse_request_head(cfd, req, 8192)) {
            ::close(cfd);
            continue;  // garbage/slow connection: ignore, keep waiting
        }

        const bool method_ok = (req.method == "GET" || req.method == "POST");
        // Lengths are not secret; only compare bytes constant-time when equal.
        const bool token_ok = req.path.size() == want_path.size() &&
                              rand::constant_time_equals(req.path.data(), req.path.size(),
                                                         want_path.data(), want_path.size());

        if (!method_ok || !token_ok) {
            // Uniform 404: no oracle about whether the token was close/correct.
            net::send_response(cfd, "404 Not Found", "not found");
            ::close(cfd);
            ++rejected_connections;
        } else if (req.content_length > im.opts.max_callback_payload_bytes) {
            // Oversized: refuse BEFORE reading anything (no unbounded read).
            net::send_response(cfd, "413 Payload Too Large", "payload too large");
            ::close(cfd);
            ++rejected_connections;
        } else {
            std::string body;
            if (req.content_length > 0 &&
                !net::read_body(cfd, body, req.content_length, req.extra)) {
                ::close(cfd);
                continue;  // incomplete body: ignore, keep waiting
            }
            net::send_response(cfd, "200 OK", "ok");
            ::close(cfd);
            CallbackResult r;
            r.status = CallbackResult::Status::Delivered;
            r.payload = std::move(body);
            r.reason = "delivered (" + std::to_string(r.payload.size()) + " bytes)";
            im.finish(std::move(r));
            return;
        }
    }
}

CallbackResult CallbackListener::wait_for_callback() {
    auto& im = *impl_;
    std::unique_lock<std::mutex> lk(im.m);
    if (im.waited) {
        // One-shot already consumed by an earlier wait.
        CallbackResult r;
        r.status = im.result.status == CallbackResult::Status::Delivered
                       ? CallbackResult::Status::AlreadyDelivered
                       : im.result.status;
        r.reason = "one-shot already consumed";
        return r;
    }
    im.cv.wait(lk, [&] { return im.done; });
    im.waited = true;
    return im.result;
}

void CallbackListener::stop() {
    auto& im = *impl_;
    im.stopped.store(true);
    im.listener.close_fd();
    if (im.worker.joinable())
        im.worker.join();
    GP_TRACE("callback: listener stopped");
}

}  // namespace gp::auth
