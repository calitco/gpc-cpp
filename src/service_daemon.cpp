// Local service daemon implementation. See include/gp/service_daemon.h for
// the hardened properties (0600 lock file, loopback-only, caps, AEAD).
#include "gp/service_daemon.h"

#include <openssl/rand.h>
#include <unistd.h>

#include <cstdio>
#include <cstring>

#include "gp/aead.h"
#include "gp/json.h"
#include "gp/secret_transport.h"
#include "gp/ws.h"
#include "net_common.h"

namespace gp::service {

namespace {

const std::string* find_header(const net::ParsedRequest& req, const char* name) {
    for (const auto& h : req.headers) {
        if (h.first == name)
            return &h.second;
    }
    return nullptr;
}

// Escape a string for embedding in JSON (client-supplied values must never
// be spliced into replies raw).
std::string json_escape(const std::string& s) {
    std::string out = "\"";
    for (char c : s) {
        switch (c) {
            case '"':
                out += "\\\"";
                break;
            case '\\':
                out += "\\\\";
                break;
            case '\n':
                out += "\\n";
                break;
            case '\r':
                out += "\\r";
                break;
            case '\t':
                out += "\\t";
                break;
            default:
                if (static_cast<unsigned char>(c) < 0x20) {
                    char b[8];
                    std::snprintf(b, sizeof b, "\\u%04x", static_cast<unsigned char>(c));
                    out += b;
                } else {
                    out += c;
                }
        }
    }
    out += "\"";
    return out;
}

// Buffered WebSocket connection: assembles full messages from frames,
// answers pings inline, and treats close/protocol errors as session end.
class WsConn {
   public:
    explicit WsConn(int fd) : fd_(fd) {}

    // Read one complete text/binary message. Returns false on EOF, timeout,
    // protocol error, or peer Close (a Close ack is sent in that case).
    bool read_message(std::string& out) {
        std::vector<unsigned char> msg;
        bool in_msg = false;
        for (;;) {
            for (;;) {
                long long fsz = ws::frame_size(buf_.data(), buf_.size());
                if (fsz == 0)
                    return false;  // malformed frame
                if (fsz > 0 && buf_.size() >= static_cast<size_t>(fsz))
                    break;
                if (!recv_more())
                    return false;  // timeout or EOF
            }
            ws::Frame f;
            size_t consumed = 0;
            if (!ws::decode_frame(buf_.data(), buf_.size(), &f, &consumed))
                return false;
            buf_.erase(buf_.begin(), buf_.begin() + static_cast<long>(consumed));

            if (f.opcode == ws::Opcode::kPing) {
                send_frame(ws::Opcode::kPong, f.payload.data(), f.payload.size());
                continue;
            }
            if (f.opcode == ws::Opcode::kClose) {
                send_frame(ws::Opcode::kClose, f.payload.data(), f.payload.size());
                return false;  // session ended by peer
            }
            if (f.opcode == ws::Opcode::kText || f.opcode == ws::Opcode::kBinary) {
                if (in_msg)
                    return false;  // new data frame while continuation pending
                in_msg = true;
                msg.clear();
                msg.insert(msg.end(), f.payload.begin(), f.payload.end());
            } else if (f.opcode == ws::Opcode::kContinuation) {
                if (!in_msg)
                    return false;  // continuation without a start frame
                msg.insert(msg.end(), f.payload.begin(), f.payload.end());
            } else {
                return false;  // reserved opcode
            }
            if (f.fin) {
                out.assign(reinterpret_cast<const char*>(msg.data()), msg.size());
                return true;
            }
        }
    }

    void send_frame(ws::Opcode op, const unsigned char* data, size_t len) {
        std::string frame = ws::encode_frame(op, data, len, false);  // server: unmasked
        if (!frame.empty())
            net::send_all(fd_, frame.data(), frame.size());
    }

   private:
    bool recv_more() {
        char tmp[4096];
        ssize_t n = ::recv(fd_, tmp, sizeof tmp, 0);
        if (n <= 0)
            return false;  // timeout or EOF
        buf_.insert(buf_.end(), tmp, tmp + n);
        return true;
    }

    int fd_;
    std::vector<unsigned char> buf_;
};

}  // namespace

ServiceDaemon::ServiceDaemon() = default;

std::unique_ptr<ServiceDaemon> ServiceDaemon::start(const DaemonConfig& cfg, std::string* err) {
    auto d = std::unique_ptr<ServiceDaemon>(new ServiceDaemon());
    if (!cfg.key.valid()) {
        if (err)
            *err = "invalid AEAD key (use ServiceKey::generate or a 0600 file)";
        return nullptr;
    }
    d->cfg_ = cfg;
    // Loopback-only by construction: no configuration path to other binds.
    d->listener_ = std::make_unique<gp::net::TcpListener>();
    if (!d->listener_->bind_to("127.0.0.1", static_cast<uint16_t>(cfg.port))) {
        if (err)
            *err = "bind to 127.0.0.1 failed";
        return nullptr;
    }
    d->port_ = d->listener_->port();

    // Lock file: pid:port, written 0600 with post-write mode verification
    // (L-2 remediation — the Rust version used default-umask creation).
    d->lock_path_ = cfg.dir + "/gpservice.lock";
    const std::string content = std::to_string(::getpid()) + ":" + std::to_string(d->port_) + "\n";
    if (!secrets::write_secret_file(d->lock_path_, content, true, err)) {
        d->listener_.reset();
        return nullptr;
    }

    d->stopping_ = false;
    // Raw pointer: the daemon outlives its acceptor (the destructor joins it),
    // and unique_ptr cannot be captured by value.
    ServiceDaemon* self = d.get();
    d->acceptor_ = std::thread([self] { self->accept_loop(); });
    return d;
}

ServiceDaemon::~ServiceDaemon() {
    stop();
}

void ServiceDaemon::stop() {
    if (stopping_.exchange(true))
        return;
    if (listener_)
        listener_->close_fd();  // unblocks accept_with_timeout
    if (acceptor_.joinable())
        acceptor_.join();
    listener_.reset();  // only after the acceptor has stopped using it
    std::vector<std::unique_ptr<std::thread>> handlers;
    {
        std::lock_guard<std::mutex> lk(threads_mu_);
        handlers.swap(handlers_);
    }
    for (auto& h : handlers) {
        if (h->joinable())
            h->join();
    }
    ::unlink(lock_path_.c_str());
}

pid_t ServiceDaemon::pid() const {
    return ::getpid();
}

void ServiceDaemon::accept_loop() {
    while (!stopping_) {
        int cfd = listener_->accept_with_timeout(100);
        if (cfd < 0)
            continue;  // timeout or stopping
        if (active_ >= cfg_.max_connections) {
            ::close(cfd);  // over the cap: drop immediately
            continue;
        }
        active_++;
        std::lock_guard<std::mutex> lk(threads_mu_);
        handlers_.push_back(std::make_unique<std::thread>([this, cfd] {
            net::set_recv_timeout(cfd, cfg_.conn_lifetime_ms);
            handle_conn(cfd);
            ::close(cfd);
            active_--;
        }));
    }
}

void ServiceDaemon::handle_conn(int fd) {
    net::ParsedRequest req;
    if (!net::parse_request_head(fd, req, 8192))
        return;

    if (req.method == "GET" && req.path == "/health") {
        net::send_response_ext(fd, "200 OK", "{\"status\":\"ok\"}", "application/json", {});
        return;
    }

    if (req.method == "GET" && req.path == "/ws") {
        const std::string* key = find_header(req, "sec-websocket-key");
        const std::string* upgrade = find_header(req, "upgrade");
        if (!key || key->empty() || !upgrade || upgrade->find("websocket") == std::string::npos) {
            net::send_response(fd, "400 Bad Request", "missing websocket headers");
            return;
        }
        const std::string resp =
            "HTTP/1.1 101 Switching Protocols\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            "Sec-WebSocket-Accept: " +
            ws::accept_key(*key) + "\r\n\r\n";
        net::send_all(fd, resp.data(), resp.size());
        ws_session(fd, *key);
        return;
    }

    net::send_response(fd, "404 Not Found", "not found");
}

bool ServiceDaemon::ws_session(int fd, const std::string& ws_key) {
    (void)ws_key;  // already validated + used for the Accept header
    WsConn conn(fd);
    for (;;) {
        // Wire format per message: 12-byte nonce || ciphertext || 16-byte tag.
        std::string wire;
        if (!conn.read_message(wire))
            return false;  // closed or protocol error
        if (wire.size() < aead::kNonceSize + aead::kTagSize) {
            return false;  // too short to be a sealed message: fail closed
        }

        unsigned char nonce[aead::kNonceSize];
        std::memcpy(nonce, wire.data(), aead::kNonceSize);
        std::string plaintext;
        if (!aead::open(cfg_.key.bytes(), nonce, wire.data() + aead::kNonceSize,
                        wire.size() - aead::kNonceSize, &plaintext)) {
            return false;  // authentication failure: fail closed, no reply
        }
        if (plaintext.size() > cfg_.max_message_bytes) {
            const char* msg = "message too large";
            conn.send_frame(ws::Opcode::kClose, reinterpret_cast<const unsigned char*>(msg),
                            strlen(msg));
            return false;
        }

        std::string reply = dispatch(plaintext);  // always valid JSON (error if bad input)
        unsigned char rnonce[aead::kNonceSize];
        if (RAND_bytes(rnonce, sizeof rnonce) != 1)
            return false;
        std::string sealed;
        if (!aead::seal(cfg_.key.bytes(), rnonce, reply.data(), reply.size(), &sealed)) {
            return false;
        }
        std::string out;
        out.append(reinterpret_cast<const char*>(rnonce), aead::kNonceSize);
        out += sealed;
        conn.send_frame(ws::Opcode::kBinary, reinterpret_cast<const unsigned char*>(out.data()),
                        out.size());
    }
}

std::string ServiceDaemon::dispatch(const std::string& plaintext) const {
    json::Value v;
    if (!json::parse_json(plaintext, cfg_.max_message_bytes, &v)) {
        return "{\"error\":\"bad_json\"}";
    }
    if (v.kind != json::Value::Kind::Object)
        return "{\"error\":\"bad_json\"}";
    const json::Value* cmd = v.find("cmd");
    if (!cmd || cmd->kind != json::Value::Kind::String)
        return "{\"error\":\"missing_cmd\"}";

    if (cmd->str == "health") {
        return "{\"status\":\"ok\"}";
    }
    if (cmd->str == "install_gui") {
        // Acknowledged only: the actual GUI install action is out of scope for
        // the C++ core (documented in the README). The echoed URL is JSON-escaped.
        const json::Value* url = v.find("url");
        std::string safe_url = (url && url->kind == json::Value::Kind::String) ? url->str : "";
        return "{\"status\":\"accepted\",\"echo_url\":" + json_escape(safe_url) + "}";
    }
    return "{\"error\":\"unknown_cmd\"}";
}

}  // namespace gp::service