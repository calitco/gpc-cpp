// Tests for finding H-1 fixes: token authentication, payload cap, timeout,
// 0600 port file, one-shot semantics.
#include <gp/callback_listener.h>
#include <gp/security_options.h>
#include <sys/stat.h>
#include <unistd.h>

#include "net_test_util.h"
#include "test_framework.h"

using gp::SecurityOptions;
using namespace gp::auth;
namespace testnet = gp::testnet;

namespace {
std::string read_file(const std::string& path) {
    std::string out;
    std::FILE* f = std::fopen(path.c_str(), "rb");
    if (!f)
        return "";
    char tmp[256];
    size_t n;
    while ((n = std::fread(tmp, 1, sizeof(tmp), f)) > 0)
        out.append(tmp, n);
    std::fclose(f);
    return out;
}

mode_t mode_of(const std::string& path) {
    struct stat st{};
    if (::stat(path.c_str(), &st) != 0)
        return 0;
    return st.st_mode & 0777;
}
}  // namespace

TEST(callback, port_file_is_0600_and_contains_port) {
    SecurityOptions o;
    CallbackListener l(o);
    std::string err;
    CHECK(l.start(&err));
    CHECK_EQ(mode_of(l.port_file()), (mode_t)0600);
    CHECK_EQ(read_file(l.port_file()), std::to_string(l.port()));
}

TEST(callback, wrong_token_is_rejected_and_one_shot_survives) {
    SecurityOptions o;
    o.callback_timeout = std::chrono::seconds(10);
    CallbackListener l(o);
    CHECK(l.start());

    // Attacker (knows the port from the 0600 file, not the token): rejected.
    std::string raw =
        testnet::http_roundtrip("127.0.0.1", l.port(), "POST", "/attacker-guess", "pwned");
    CHECK(testnet::status_of(raw).find("404") != std::string::npos);

    // Legitimate browser delivery still works afterwards.
    const std::string payload = "globalprotectcallback:eyJzZXNzaW9uIjoiMTIzIn0";
    raw = testnet::http_roundtrip("127.0.0.1", l.port(), "POST", l.url_path(), payload);
    CHECK(testnet::status_of(raw).find("200") != std::string::npos);

    CallbackResult r = l.wait_for_callback();
    CHECK(r.status == CallbackResult::Status::Delivered);
    CHECK_EQ(r.payload, payload);
}

TEST(callback, oversized_payload_is_refused_before_reading) {
    SecurityOptions o;
    o.callback_timeout = std::chrono::seconds(10);
    o.max_callback_payload_bytes = 64;
    CallbackListener l(o);
    CHECK(l.start());

    // Declare a huge Content-Length: server must answer 413 without reading.
    std::string raw =
        testnet::http_roundtrip("127.0.0.1", l.port(), "POST", l.url_path(), std::string(100, 'A'));
    CHECK(testnet::status_of(raw).find("413") != std::string::npos);

    // One-shot still available for the real (small) delivery.
    raw = testnet::http_roundtrip("127.0.0.1", l.port(), "POST", l.url_path(), "small");
    CHECK(testnet::status_of(raw).find("200") != std::string::npos);
    CallbackResult r = l.wait_for_callback();
    CHECK(r.status == CallbackResult::Status::Delivered);
    CHECK_EQ(r.payload, std::string("small"));
}

TEST(callback, times_out_when_nothing_arrives) {
    SecurityOptions o;
    o.callback_timeout = std::chrono::milliseconds(300);
    CallbackListener l(o);
    CHECK(l.start());
    auto t0 = std::chrono::steady_clock::now();
    CallbackResult r = l.wait_for_callback();
    auto elapsed = std::chrono::steady_clock::now() - t0;
    CHECK(r.status == CallbackResult::Status::Timeout);
    CHECK(elapsed >= std::chrono::milliseconds(250));
}

TEST(callback, one_shot_is_consumed) {
    SecurityOptions o;
    o.callback_timeout = std::chrono::seconds(10);
    CallbackListener l(o);
    CHECK(l.start());
    testnet::http_roundtrip("127.0.0.1", l.port(), "POST", l.url_path(), "x");
    CallbackResult r1 = l.wait_for_callback();
    CHECK(r1.status == CallbackResult::Status::Delivered);
    CallbackResult r2 = l.wait_for_callback();
    CHECK(r2.status == CallbackResult::Status::AlreadyDelivered);
}

TEST(callback, get_without_body_delivers_empty_payload) {
    SecurityOptions o;
    o.callback_timeout = std::chrono::seconds(10);
    CallbackListener l(o);
    CHECK(l.start());
    std::string raw = testnet::http_roundtrip("127.0.0.1", l.port(), "GET", l.url_path());
    CHECK(testnet::status_of(raw).find("200") != std::string::npos);
    CallbackResult r = l.wait_for_callback();
    CHECK(r.status == CallbackResult::Status::Delivered);
    CHECK(r.payload.empty());
}

int main() {
    return gp::test::Registry::instance().run_all();
}
