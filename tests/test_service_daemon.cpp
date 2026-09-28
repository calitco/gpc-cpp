// Tests for gp::service::ServiceDaemon — the local loopback WS/AEAD daemon.
// Uses raw POSIX sockets as the client (no new dependencies). Client frames
// are masked per RFC 6455; server frames arrive unmasked.
#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <openssl/rand.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cctype>
#include <cstring>
#include <string>
#include <vector>

#include "gp/aead.h"
#include "gp/json.h"
#include "gp/service_daemon.h"
#include "gp/ws.h"
#include "net_common.h"
#include "test_framework.h"

using gp::service::DaemonConfig;
using gp::service::ServiceDaemon;
using gp::service::ServiceKey;

namespace {

int connect_to(int port) {
    int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
        return -1;
    sockaddr_in sa{};
    sa.sin_family = AF_INET;
    sa.sin_port = htons(static_cast<uint16_t>(port));
    if (::inet_pton(AF_INET, "127.0.0.1", &sa.sin_addr) != 1) {
        ::close(fd);
        return -1;
    }
    gp::net::set_recv_timeout(fd, 5000);  // tests must never hang
    if (::connect(fd, reinterpret_cast<sockaddr*>(&sa), sizeof(sa)) != 0) {
        ::close(fd);
        return -1;
    }
    return fd;
}

// Read a full HTTP response (server sends Connection: close). For the 101
// handshake there is no body; Content-Length is absent and treated as 0.
bool read_response(int fd, std::string* head, std::string* body) {
    std::string raw;
    char tmp[4096];
    while (raw.find("\r\n\r\n") == std::string::npos) {
        ssize_t n = ::recv(fd, tmp, sizeof tmp, 0);
        if (n <= 0)
            return false;
        raw.append(tmp, static_cast<size_t>(n));
        if (raw.size() > 65536)
            return false;
    }
    size_t hlen = raw.find("\r\n\r\n") + 4;
    *head = raw.substr(0, hlen);

    std::string lower = *head;
    for (auto& c : lower)
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    size_t content_length = 0;
    size_t pos = lower.find("content-length: ");
    if (pos != std::string::npos)
        content_length = std::stoul(lower.substr(pos + 16));

    raw.erase(0, hlen);
    while (raw.size() < content_length) {
        ssize_t n = ::recv(fd, tmp, sizeof tmp, 0);
        if (n <= 0)
            return false;
        raw.append(tmp, static_cast<size_t>(n));
    }
    *body = raw.substr(0, content_length);
    return true;
}

std::string header_value(const std::string& head, const std::string& name) {
    std::string lower_head = head, lower_name = name;
    for (auto& c : lower_head)
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    for (auto& c : lower_name)
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    size_t pos = lower_head.find(lower_name + ": ");
    if (pos == std::string::npos)
        return "";
    size_t start = pos + lower_name.size() + 2;
    size_t end = head.find("\r\n", start);
    return head.substr(start, end - start);
}
bool ws_handshake(int fd, const std::string& key, std::string* accept_out) {
    const std::string req =
        "GET /ws HTTP/1.1\r\n"
        "Host: 127.0.0.1\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Key: " +
        key +
        "\r\n"
        "Sec-WebSocket-Version: 13\r\n\r\n";
    gp::net::send_all(fd, req.data(), req.size());
    std::string head, body;
    if (!read_response(fd, &head, &body))
        return false;
    *accept_out = header_value(head, "sec-websocket-accept");
    return head.rfind("HTTP/1.1 101", 0) == 0;
}

void ws_send(int fd, gp::ws::Opcode op, const std::string& payload) {
    std::string frame = gp::ws::encode_frame(
        op, reinterpret_cast<const unsigned char*>(payload.data()), payload.size(), true);
    gp::net::send_all(fd, frame.data(), frame.size());
}

// Read the next data (text/binary) frame. Pings are answered and skipped;
// a server Close or EOF/timeout returns false.
bool ws_recv(int fd, std::string* payload) {
    std::vector<unsigned char> buf;
    for (;;) {
        // Buffer until one complete frame is available.
        for (;;) {
            long long fsz = gp::ws::frame_size(buf.data(), buf.size());
            if (fsz == 0)
                return false;
            if (fsz > 0 && buf.size() >= static_cast<size_t>(fsz))
                break;
            char tmp[4096];
            ssize_t n = ::recv(fd, tmp, sizeof tmp, 0);
            if (n <= 0)
                return false;
            buf.insert(buf.end(), tmp, tmp + n);
        }
        gp::ws::Frame f;
        size_t consumed = 0;
        if (!gp::ws::decode_frame(buf.data(), buf.size(), &f, &consumed))
            return false;
        buf.erase(buf.begin(), buf.begin() + static_cast<long>(consumed));

        if (f.opcode == gp::ws::Opcode::kPing) {
            std::string pong = gp::ws::encode_frame(gp::ws::Opcode::kPong, f.payload.data(),
                                                    f.payload.size(), true);
            gp::net::send_all(fd, pong.data(), pong.size());
            continue;  // wait for the next frame
        }
        if (f.opcode != gp::ws::Opcode::kBinary && f.opcode != gp::ws::Opcode::kText)
            return false;  // close or reserved
        payload->assign(reinterpret_cast<const char*>(f.payload.data()), f.payload.size());
        return true;
    }
}

// Read one raw frame (any opcode) — used to assert on Close frames.
bool ws_recv_frame(int fd, gp::ws::Frame* f) {
    std::vector<unsigned char> buf;
    for (;;) {
        long long fsz = gp::ws::frame_size(buf.data(), buf.size());
        if (fsz == 0)
            return false;
        if (fsz > 0 && buf.size() >= static_cast<size_t>(fsz))
            break;
        char tmp[4096];
        ssize_t n = ::recv(fd, tmp, sizeof tmp, 0);
        if (n <= 0)
            return false;
        buf.insert(buf.end(), tmp, tmp + n);
    }
    size_t consumed = 0;
    return gp::ws::decode_frame(buf.data(), buf.size(), f, &consumed);
}

// Wire format: 12-byte nonce || ciphertext || 16-byte tag.
std::string seal_msg(const ServiceKey& key, const std::string& pt) {
    unsigned char nonce[gp::aead::kNonceSize];
    if (RAND_bytes(nonce, sizeof nonce) != 1)
        return "";
    std::string sealed;
    if (!gp::aead::seal(key.bytes(), nonce, pt.data(), pt.size(), &sealed))
        return "";
    std::string wire(reinterpret_cast<const char*>(nonce), sizeof nonce);
    wire += sealed;
    return wire;
}

bool open_msg(const ServiceKey& key, const std::string& wire, std::string* pt) {
    if (wire.size() < gp::aead::kNonceSize + gp::aead::kTagSize)
        return false;
    unsigned char nonce[gp::aead::kNonceSize];
    std::memcpy(nonce, wire.data(), sizeof nonce);
    return gp::aead::open(key.bytes(), nonce, wire.data() + gp::aead::kNonceSize,
                          wire.size() - gp::aead::kNonceSize, pt);
}

std::string make_dir() {
    char tmpl[] = "/tmp/gpsvc_test_XXXXXX";
    char* dir = mkdtemp(tmpl);
    return dir ? std::string(dir) : std::string();
}

std::string read_file(const std::string& path) {
    int fd = ::open(path.c_str(), O_RDONLY);
    if (fd < 0)
        return "";
    std::string out;
    char tmp[256];
    ssize_t n;
    while ((n = ::read(fd, tmp, sizeof tmp)) > 0)
        out.append(tmp, static_cast<size_t>(n));
    ::close(fd);
    return out;
}

// Test daemon config: short per-connection lifetime so stop() returns
// quickly even if a check throws with a client socket still open.
DaemonConfig make_cfg(const std::string& dir) {
    DaemonConfig cfg;
    cfg.dir = dir;
    cfg.key = ServiceKey::generate();
    cfg.conn_lifetime_ms = 2000;
    return cfg;
}

TEST(service, aead_roundtrip_and_tamper_rejection) {
    ServiceKey key = ServiceKey::generate();
    REQUIRE(key.valid());
    const std::string pt = "hello daemon";

    std::string wire = seal_msg(key, pt);
    REQUIRE(!wire.empty());
    std::string out;
    CHECK(open_msg(key, wire, &out));
    CHECK_EQ(out, pt);

    // Tampered ciphertext must fail authentication.
    wire[gp::aead::kNonceSize] ^= 0x01;
    CHECK(!open_msg(key, wire, &out));

    // Tampered tag must also fail.
    std::string wire2 = seal_msg(key, pt);
    REQUIRE(!wire2.empty());
    wire2.back() ^= 0x80;
    CHECK(!open_msg(key, wire2, &out));

    // A different key must not open the message.
    ServiceKey other = ServiceKey::generate();
    std::string wire3 = seal_msg(key, pt);
    REQUIRE(!wire3.empty());
    CHECK(!open_msg(other, wire3, &out));
}

TEST(service, start_refuses_invalid_key) {
    const std::string dir = make_dir();
    REQUIRE(!dir.empty());
    DaemonConfig cfg;
    cfg.dir = dir;  // key left empty/invalid
    std::string err;
    auto d = ServiceDaemon::start(cfg, &err);
    CHECK(d == nullptr);
    CHECK(!err.empty());
    ::rmdir(dir.c_str());
}

TEST(service, health_endpoint_and_lock_file) {
    const std::string dir = make_dir();
    REQUIRE(!dir.empty());
    DaemonConfig cfg = make_cfg(dir);
    auto d = ServiceDaemon::start(cfg);
    REQUIRE(d != nullptr);

    // Lock file: 0600 (L-2), pid:port content.
    const std::string lock_path = dir + "/gpservice.lock";
    struct stat st;
    CHECK(::stat(lock_path.c_str(), &st) == 0);
    CHECK_EQ(st.st_mode & 0777, 0600);
    CHECK_EQ(read_file(lock_path),
             std::to_string(d->pid()) + ":" + std::to_string(d->port()) + "\n");

    // /health over plain HTTP.
    int fd = connect_to(d->port());
    REQUIRE(fd >= 0);
    const std::string req = "GET /health HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n";
    gp::net::send_all(fd, req.data(), req.size());
    std::string head, body;
    CHECK(read_response(fd, &head, &body));
    CHECK(head.rfind("HTTP/1.1 200", 0) == 0);
    CHECK_EQ(body, std::string("{\"status\":\"ok\"}"));
    ::close(fd);

    // Unknown path → 404.
    fd = connect_to(d->port());
    REQUIRE(fd >= 0);
    const std::string req404 = "GET /nope HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n";
    gp::net::send_all(fd, req404.data(), req404.size());
    CHECK(read_response(fd, &head, &body));
    CHECK(head.rfind("HTTP/1.1 404", 0) == 0);
    ::close(fd);

    d->stop();
    // Lock file removed on clean shutdown.
    CHECK(::access(lock_path.c_str(), F_OK) != 0);
    ::rmdir(dir.c_str());
}
TEST(service, ws_handshake_and_aead_command_roundtrip) {
    const std::string dir = make_dir();
    REQUIRE(!dir.empty());
    DaemonConfig cfg = make_cfg(dir);
    auto d = ServiceDaemon::start(cfg);
    REQUIRE(d != nullptr);

    int fd = connect_to(d->port());
    REQUIRE(fd >= 0);
    // RFC 6455 section 1.3 sample key with its known answer.
    const std::string client_key = "dGhlIHNhbXBsZSBub25jZQ==";
    std::string accept;
    CHECK(ws_handshake(fd, client_key, &accept));
    CHECK_EQ(accept, gp::ws::accept_key(client_key));
    CHECK_EQ(accept, std::string("s3pPLMBiTxaQ9kYGzzhZRbK+xOo="));

    // Sealed health command → sealed JSON reply.
    ws_send(fd, gp::ws::Opcode::kText, seal_msg(cfg.key, "{\"cmd\":\"health\"}"));
    std::string wire;
    CHECK(ws_recv(fd, &wire));
    std::string pt;
    CHECK(open_msg(cfg.key, wire, &pt));
    CHECK_EQ(pt, std::string("{\"status\":\"ok\"}"));

    // install_gui with quote-bearing URL: the reply must be valid JSON whose
    // echo_url round-trips exactly (server-side escaping).
    const std::string evil = "http://x/?a=1&b=\"injected\"";
    const std::string req =
        "{\"cmd\":\"install_gui\",\"url\":\"http://x/?a=1&b=\\\"injected\\\"\"}";
    ws_send(fd, gp::ws::Opcode::kText, seal_msg(cfg.key, req));
    CHECK(ws_recv(fd, &wire));
    CHECK(open_msg(cfg.key, wire, &pt));
    gp::json::Value v;
    CHECK(gp::json::parse_json(pt, 1 << 20, &v));
    const gp::json::Value* url = v.find("echo_url");
    REQUIRE(url != nullptr);
    CHECK_EQ(url->str, evil);

    // Unknown command → error reply (session stays alive).
    ws_send(fd, gp::ws::Opcode::kText, seal_msg(cfg.key, "{\"cmd\":\"nope\"}"));
    CHECK(ws_recv(fd, &wire));
    CHECK(open_msg(cfg.key, wire, &pt));
    CHECK(pt.find("unknown_cmd") != std::string::npos);

    ::close(fd);
    d->stop();
    ::rmdir(dir.c_str());
}

TEST(service, tampered_message_ends_session_fail_closed) {
    const std::string dir = make_dir();
    REQUIRE(!dir.empty());
    DaemonConfig cfg = make_cfg(dir);
    auto d = ServiceDaemon::start(cfg);
    REQUIRE(d != nullptr);

    int fd = connect_to(d->port());
    REQUIRE(fd >= 0);
    std::string accept;
    CHECK(ws_handshake(fd, "dGhlIHNhbXBsZSBub25jZQ==", &accept));

    // Sealed with the WRONG key: AEAD authentication must fail server-side and
    // the session must end without any reply (fail closed).
    ServiceKey wrong = ServiceKey::generate();
    ws_send(fd, gp::ws::Opcode::kText, seal_msg(wrong, "{\"cmd\":\"health\"}"));
    char tmp[64];
    ssize_t n = ::recv(fd, tmp, sizeof tmp, 0);
    CHECK(n == 0);  // clean EOF, no data

    ::close(fd);
    d->stop();
    ::rmdir(dir.c_str());
}

TEST(service, overlarge_message_gets_close_frame) {
    const std::string dir = make_dir();
    REQUIRE(!dir.empty());
    DaemonConfig cfg = make_cfg(dir);
    cfg.max_message_bytes = 16;  // tiny cap for the test
    auto d = ServiceDaemon::start(cfg);
    REQUIRE(d != nullptr);

    int fd = connect_to(d->port());
    REQUIRE(fd >= 0);
    std::string accept;
    CHECK(ws_handshake(fd, "dGhlIHNhbXBsZSBub25jZQ==", &accept));

    // 32-byte plaintext exceeds the 16-byte cap.
    ws_send(fd, gp::ws::Opcode::kText, seal_msg(cfg.key, std::string(32, 'x')));
    gp::ws::Frame f;
    CHECK(ws_recv_frame(fd, &f));
    CHECK(f.opcode == gp::ws::Opcode::kClose);

    ::close(fd);
    d->stop();
    ::rmdir(dir.c_str());
}

TEST(service, ws_upgrade_requires_headers) {
    const std::string dir = make_dir();
    REQUIRE(!dir.empty());
    DaemonConfig cfg = make_cfg(dir);
    auto d = ServiceDaemon::start(cfg);
    REQUIRE(d != nullptr);

    int fd = connect_to(d->port());
    REQUIRE(fd >= 0);
    const std::string req = "GET /ws HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n";
    gp::net::send_all(fd, req.data(), req.size());
    std::string head, body;
    CHECK(read_response(fd, &head, &body));
    CHECK(head.rfind("HTTP/1.1 400", 0) == 0);

    ::close(fd);
    d->stop();
    ::rmdir(dir.c_str());
}

}  // namespace

int main() {
    return gp::test::Registry::instance().run_all();
}
