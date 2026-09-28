// Tests for gp::ws — RFC 6455 frame primitives (pure byte-level, no sockets).
#include <string>
#include <vector>

#include "gp/ws.h"
#include "test_framework.h"

using gp::ws::Frame;
using gp::ws::Opcode;

namespace {

std::vector<unsigned char> bytes(const std::string& s) {
    return {s.begin(), s.end()};
}

// Deterministic masked frame: FIN+opcode, mask bit set, known 4-byte key.
std::string masked_frame(uint8_t opcode, const std::vector<unsigned char>& payload,
                         unsigned char k0, unsigned char k1, unsigned char k2, unsigned char k3) {
    std::string out;
    out.push_back(static_cast<char>(0x80 | opcode));
    CHECK(payload.size() < 126);  // these tests use the small length form only
    out.push_back(static_cast<char>(0x80 | payload.size()));
    out += std::string({static_cast<char>(k0), static_cast<char>(k1), static_cast<char>(k2),
                        static_cast<char>(k3)});
    unsigned char key[4] = {k0, k1, k2, k3};
    for (size_t i = 0; i < payload.size(); ++i)
        out.push_back(static_cast<char>(payload[i] ^ key[i % 4]));
    return out;
}

}  // namespace

TEST(ws, accept_key_matches_rfc6455_vector) {
    // RFC 6455 section 1.3 example.
    CHECK_EQ(gp::ws::accept_key("dGhlIHNhbXBsZSBub25jZQ=="), "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
}

TEST(ws, small_unmasked_frame_roundtrip) {
    const std::string pt = "hello tunnel";
    std::string enc = gp::ws::encode_frame(Opcode::kBinary, bytes(pt).data(), pt.size(), false);
    CHECK(!enc.empty());
    Frame f;
    size_t consumed = 0;
    CHECK(gp::ws::decode_frame(reinterpret_cast<const unsigned char*>(enc.data()), enc.size(), &f,
                               &consumed));
    CHECK_EQ(consumed, enc.size());
    CHECK(f.fin);
    CHECK(f.opcode == Opcode::kBinary);
    CHECK_EQ(std::string(f.payload.begin(), f.payload.end()), pt);
}

TEST(ws, empty_payload_frame_roundtrip) {
    std::string enc = gp::ws::encode_frame(Opcode::kPing, nullptr, 0, false);
    CHECK(!enc.empty());
    Frame f;
    size_t consumed = 0;
    CHECK(gp::ws::decode_frame(reinterpret_cast<const unsigned char*>(enc.data()), enc.size(), &f,
                               &consumed));
    CHECK_EQ(consumed, 2u);
    CHECK(f.opcode == Opcode::kPing);
    CHECK(f.payload.empty());
}

TEST(ws, sixteen_bit_length_form_roundtrip) {
    // 300 bytes: forces the 126 (two-byte) length form.
    std::vector<unsigned char> pt(300);
    for (size_t i = 0; i < pt.size(); ++i)
        pt[i] = static_cast<unsigned char>(i * 7 + 1);
    std::string enc = gp::ws::encode_frame(Opcode::kBinary, pt.data(), pt.size(), false);
    CHECK(!enc.empty());
    Frame f;
    size_t consumed = 0;
    CHECK(gp::ws::decode_frame(reinterpret_cast<const unsigned char*>(enc.data()), enc.size(), &f,
                               &consumed));
    CHECK_EQ(consumed, enc.size());
    CHECK(f.payload == pt);
}

TEST(ws, sixty_four_bit_length_form_roundtrip) {
    // 70000 bytes: forces the 127 (eight-byte) length form.
    std::vector<unsigned char> pt(70000);
    for (size_t i = 0; i < pt.size(); ++i)
        pt[i] = static_cast<unsigned char>(i & 0xFF);
    std::string enc = gp::ws::encode_frame(Opcode::kText, pt.data(), pt.size(), false);
    CHECK(!enc.empty());
    Frame f;
    size_t consumed = 0;
    CHECK(gp::ws::decode_frame(reinterpret_cast<const unsigned char*>(enc.data()), enc.size(), &f,
                               &consumed));
    CHECK_EQ(consumed, enc.size());
    CHECK(f.opcode == Opcode::kText);
    CHECK(f.payload == pt);
}

TEST(ws, masked_client_frame_roundtrip) {
    // encode_frame picks a random mask key; the decoder must unmask correctly.
    const std::string pt = "masked payload";
    std::string enc = gp::ws::encode_frame(Opcode::kText, bytes(pt).data(), pt.size(), true);
    CHECK(!enc.empty());
    // The mask bit is set and a 4-byte key follows the header.
    CHECK((static_cast<unsigned char>(enc[1]) & 0x80) != 0);
    Frame f;
    size_t consumed = 0;
    CHECK(gp::ws::decode_frame(reinterpret_cast<const unsigned char*>(enc.data()), enc.size(), &f,
                               &consumed));
    CHECK_EQ(consumed, enc.size());
    CHECK_EQ(std::string(f.payload.begin(), f.payload.end()), pt);
}

TEST(ws, decodes_deterministic_masked_frame) {
    // Hand-built frame with a known mask key: verifies the exact XOR schedule.
    const std::vector<unsigned char> pt = {'a', 'b', 'c', 'd', 'e'};
    std::string enc = masked_frame(0x2, pt, 0x37, 0x6f, 0x67, 0xe3);
    Frame f;
    size_t consumed = 0;
    CHECK(gp::ws::decode_frame(reinterpret_cast<const unsigned char*>(enc.data()), enc.size(), &f,
                               &consumed));
    CHECK_EQ(consumed, enc.size());
    CHECK(f.payload == pt);
}

TEST(ws, rejects_reserved_bits) {
    std::string enc = gp::ws::encode_frame(Opcode::kBinary, nullptr, 0, false);
    // Set RSV1.
    enc[0] = static_cast<char>(static_cast<unsigned char>(enc[0]) | 0x40);
    Frame f;
    size_t consumed = 0;
    CHECK(!gp::ws::decode_frame(reinterpret_cast<const unsigned char*>(enc.data()), enc.size(), &f,
                                &consumed));
    CHECK_EQ(gp::ws::frame_size(reinterpret_cast<const unsigned char*>(enc.data()), enc.size()), 0);
}

TEST(ws, rejects_control_frame_longer_than_125) {
    // Close frame claiming a 126-byte payload via the 16-bit length form.
    std::string bad;
    bad.push_back(static_cast<char>(0x88));  // FIN + Close
    bad.push_back(static_cast<char>(126));
    bad.push_back(0x00);
    bad.push_back(126);
    bad.append(126, 'x');
    Frame f;
    size_t consumed = 0;
    CHECK(!gp::ws::decode_frame(reinterpret_cast<const unsigned char*>(bad.data()), bad.size(), &f,
                                &consumed));
    CHECK_EQ(gp::ws::frame_size(reinterpret_cast<const unsigned char*>(bad.data()), bad.size()), 0);
}

TEST(ws, rejects_control_frame_without_fin) {
    std::string bad;
    bad.push_back(static_cast<char>(Opcode::kClose));  // no FIN bit
    bad.push_back(1);
    bad.push_back('x');
    Frame f;
    size_t consumed = 0;
    CHECK(!gp::ws::decode_frame(reinterpret_cast<const unsigned char*>(bad.data()), bad.size(), &f,
                                &consumed));
    CHECK_EQ(gp::ws::frame_size(reinterpret_cast<const unsigned char*>(bad.data()), bad.size()), 0);
}

TEST(ws, truncated_frame_is_detected) {
    const std::string pt = "truncated me";
    std::string enc = gp::ws::encode_frame(Opcode::kBinary, bytes(pt).data(), pt.size(), false);
    // One byte short.
    Frame f;
    size_t consumed = 0;
    CHECK(!gp::ws::decode_frame(reinterpret_cast<const unsigned char*>(enc.data()), enc.size() - 1,
                                &f, &consumed));
    CHECK_EQ(gp::ws::frame_size(reinterpret_cast<const unsigned char*>(enc.data()), enc.size() - 1),
             -1);
    // Two header bytes only.
    std::string hdr = enc.substr(0, 2);
    CHECK(!gp::ws::decode_frame(reinterpret_cast<const unsigned char*>(hdr.data()), hdr.size(), &f,
                                &consumed));
}

TEST(ws, oversized_payload_header_rejected_without_allocation) {
    // 127-form header claiming 16 MiB + 1 — rejected from the header alone.
    std::string bad;
    bad.push_back(static_cast<char>(0x82));  // FIN + binary
    bad.push_back(127);
    unsigned char len8[8] = {0, 0, 0, 1, 0, 0, 0, 1};  // 16*1024*1024 + 1
    bad.append(reinterpret_cast<const char*>(len8), sizeof len8);
    bad.push_back('x');
    Frame f;
    size_t consumed = 0;
    CHECK(!gp::ws::decode_frame(reinterpret_cast<const unsigned char*>(bad.data()), bad.size(), &f,
                                &consumed));
    CHECK_EQ(gp::ws::frame_size(reinterpret_cast<const unsigned char*>(bad.data()), bad.size()), 0);
}

TEST(ws, multiple_frames_in_one_buffer) {
    std::string buf =
        gp::ws::encode_frame(Opcode::kText, reinterpret_cast<const unsigned char*>("ab"), 2, false);
    buf += gp::ws::encode_frame(Opcode::kClose, nullptr, 0, false);
    Frame f1, f2;
    size_t c1 = 0, c2 = 0;
    CHECK(gp::ws::decode_frame(reinterpret_cast<const unsigned char*>(buf.data()), buf.size(), &f1,
                               &c1));
    CHECK_EQ(c1, 4u);  // 2 header + 2 payload
    CHECK_EQ(std::string(f1.payload.begin(), f1.payload.end()), "ab");
    CHECK(gp::ws::decode_frame(reinterpret_cast<const unsigned char*>(buf.data()) + c1,
                               buf.size() - c1, &f2, &c2));
    CHECK_EQ(c2, 2u);
    CHECK(f2.opcode == Opcode::kClose);
}

int main() {
    return gp::test::Registry::instance().run_all();
}
