// Minimal RFC 6455 WebSocket primitives for the local service daemon.
// Pure byte-level functions (no sockets) so they are fully unit-testable:
//  - Sec-WebSocket-Accept computation (SHA-1 + Base64, OpenSSL);
//  - frame encode/decode with 7/16/64-bit length forms and masking;
//  - strict validation of reserved bits, control-frame size limits.
#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace gp::ws {

enum class Opcode : uint8_t {
    kContinuation = 0x0,
    kText = 0x1,
    kBinary = 0x2,
    kClose = 0x8,
    kPing = 0x9,
    kPong = 0xA,
};

// RFC 6455 section 4.2.2: base64(SHA1(key || GUID)).
std::string accept_key(const std::string& client_key);

struct Frame {
    bool fin = true;
    Opcode opcode = Opcode::kBinary;
    std::vector<unsigned char> payload;
};

// Encode one frame. `mask` must be false for server->client (RFC 6455:
// servers MUST NOT mask) and true for client->server.
std::string encode_frame(Opcode op, const unsigned char* data, size_t len, bool mask);

// Decode exactly one frame from the start of buf. On success sets *consumed
// to the number of bytes used. Fails on truncated input, reserved bits set,
// control frames longer than 125 bytes, or malformed length forms.
bool decode_frame(const unsigned char* buf, size_t len, Frame* out, size_t* consumed);

// Total byte size (header + payload) of the frame starting at buf:
//   > 0  complete frame size
//   -1   header valid but more bytes are needed (truncated)
//    0   malformed (reserved bits, bad control-frame size, oversized)
long long frame_size(const unsigned char* buf, size_t len);

}  // namespace gp::ws