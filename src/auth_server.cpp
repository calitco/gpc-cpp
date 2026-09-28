#include "gp/auth_server.h"

#include <unistd.h>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <mutex>
#include <sstream>
#include <thread>

#include "gp/html_escape.h"
#include "gp/random.h"
#include "gp/trace.h"
#include "net_common.h"

namespace gp::auth {

struct AuthServer::Impl {
    const SecurityOptions& opts;
    net::TcpListener listener;
    std::string token;
    uint16_t port = 0;
    std::string bind_address;
    AuthServerConfig cfg;
    bool started = false;
    std::atomic<bool> stopped{false};
    std::thread worker;
    std::mutex m;
    std::condition_variable cv;
    bool done = false;
    AuthServerResult result;

    explicit Impl(const SecurityOptions& o) : opts(o) {}

    void finish(AuthServerResult r) {
        GP_TRACE("auth-server: ", r.reason);  // reasons are log-safe (no tokens)
        {
            std::lock_guard<std::mutex> lk(m);
            result = std::move(r);
            done = true;
        }
        cv.notify_all();
        stopped.store(true);
        listener.close_fd();
    }
};

AuthServer::AuthServer(const SecurityOptions& opts) : impl_(std::make_unique<Impl>(opts)) {}

AuthServer::~AuthServer() {
    stop();
}

namespace {
// Locally generated template. The ONLY dynamic values are escaped before
// interpolation; there is no path where raw portal HTML reaches the page.
std::string render_page(const AuthServerConfig& cfg) {
    std::ostringstream oss;
    oss << "<!DOCTYPE html>\n<html><head><meta charset=\"utf-8\">\n"
        << "<title>" << html::escape_text(cfg.page_title) << "</title></head>\n"
        << "<body style=\"font-family:sans-serif;max-width:640px;margin:2em auto;\">\n"
        << "<h1>" << html::escape_text(cfg.page_title) << "</h1>\n"
        << "<p>Your browser is being used to complete a GlobalProtect "
           "authentication request.</p>\n";
    if (!cfg.portal_display_url.empty()) {
        oss << "<p>Portal: <code>" << html::escape_text(cfg.portal_display_url) << "</code></p>\n";
    }
    oss << "<p>If you did not start a VPN connection, close this page.</p>\n"
        << "</body></html>\n";
    return oss.str();
}
}  // namespace

bool AuthServer::start(const AuthServerConfig& cfg, std::string* err) {
    auto& im = *impl_;
    if (im.started) {
        if (err)
            *err = "server already started";
        return false;
    }

    // Non-loopback bind requires the explicit opt-in switch. This is enforced
    // at the API level, not only in CLI parsing.
    if (!net::TcpListener::is_loopback(cfg.bind_address) && !im.opts.allow_remote_callback_bind) {
        if (err)
            *err = "refusing to bind " + cfg.bind_address +
                   ": non-loopback bind requires --allow-remote-callback";
        return false;
    }

    // Fail closed on a malformed redirect target instead of panicking/hanging.
    if (cfg.redirect_url.has_value() &&
        !html::valid_redirect_target(*cfg.redirect_url, im.opts.allowed_redirect_hosts)) {
        if (err)
            *err = "refusing to serve: invalid redirect target '" + *cfg.redirect_url + "'";
        return false;
    }

    im.token = rand::to_base64url(rand::random_bytes(32));
    if (!im.listener.bind_to(cfg.bind_address, cfg.port)) {
        if (err)
            *err = "cannot bind auth server to " + cfg.bind_address;
        return false;
    }
    im.port = im.listener.port();
    im.bind_address = cfg.bind_address;
    im.cfg = cfg;
    im.started = true;
    im.worker = std::thread([this] { worker_loop(); });
    GP_TRACE("auth-server: listening on ", cfg.bind_address, ":", im.port,
             " (one-shot URL hidden)");
    return true;
}

void AuthServer::worker_loop() {
    auto& im = *impl_;
    auto deadline = std::chrono::steady_clock::now() + im.opts.auth_server_timeout;
    const std::string want_path = "/" + im.token;
    std::size_t total_requests = 0;

    while (!im.stopped.load()) {
        if (total_requests >= im.opts.max_auth_server_requests) {
            AuthServerResult r;
            r.status = AuthServerResult::Status::RequestLimit;
            r.reason = "request cap reached without a valid visit";
            im.finish(std::move(r));
            return;
        }
        auto now = std::chrono::steady_clock::now();
        if (now >= deadline) {
            AuthServerResult r;
            r.status = AuthServerResult::Status::Timeout;
            r.reason = "deadline reached (" + std::to_string(total_requests) + " request(s) seen)";
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
            ++total_requests;
            continue;
        }
        ++total_requests;

        const bool path_ok = req.path.size() == want_path.size() &&
                             rand::constant_time_equals(req.path.data(), req.path.size(),
                                                        want_path.data(), want_path.size());
        if (!path_ok || (req.method != "GET" && req.method != "HEAD")) {
            net::send_response(cfd, "404 Not Found", "not found");
            ::close(cfd);
            continue;  // uniform 404: no token oracle
        }

        if (req.content_length > 65536) {
            net::send_response(cfd, "413 Payload Too Large", "too large");
            ::close(cfd);
            continue;
        }

        // Valid visit: consume the one-shot.
        if (im.cfg.redirect_url.has_value()) {
            net::send_response_ext(cfd, "302 Found", "", "text/plain",
                                   {"Location: " + *im.cfg.redirect_url});
        } else {
            const std::string page = render_page(im.cfg);
            net::send_response(cfd, "200 OK", page, "text/html; charset=utf-8");
        }
        ::close(cfd);
        AuthServerResult r;
        r.status = AuthServerResult::Status::Visited;
        r.reason = "one-shot URL visited";
        im.finish(std::move(r));
        return;
    }
}

uint16_t AuthServer::port() const {
    return impl_->port;
}
const std::string& AuthServer::token() const {
    return impl_->token;
}
std::string AuthServer::url() const {
    return "http://" + impl_->bind_address + ":" + std::to_string(impl_->port) + "/" + impl_->token;
}

AuthServerResult AuthServer::wait_for_visit() {
    auto& im = *impl_;
    if (!im.started) {
        AuthServerResult r;
        r.status = AuthServerResult::Status::Error;
        r.reason = "server not started";
        return r;
    }
    std::unique_lock<std::mutex> lk(im.m);
    im.cv.wait(lk, [&] { return im.done; });
    return im.result;
}

void AuthServer::stop() {
    auto& im = *impl_;
    if (!im.started)
        return;
    im.stopped.store(true);
    im.listener.close_fd();
    if (im.worker.joinable())
        im.worker.join();
    GP_TRACE("auth-server: stopped");
}

}  // namespace gp::auth
