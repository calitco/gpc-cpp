// WebSocket primitives implementation. See include/gp/ws.h.
#include "gp/ws.h"

#include <openssl/evp.h>
#include <openssl/rand.h>

namespace gp::ws {

namespace {
constexpr size_t kMaxPayload = 16 * 1024 * 1024;  // sanity cap per frame
}  // namespace

std::string accept_key(const std::string& client_key) {
    const char guid[] = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len = 0;
    const std::string input = client_key + guid;
    if (EVP_Digest(input.data(), input.size(), hash, &hash_len, EVP_sha1(), nullptr) != 1) {
        return std::string();
    }

    unsigned char b64[EVP_MAX_MD_SIZE * 2];
    int n = EVP_EncodeBlock(b64, hash, static_cast<int>(hash_len));
    return std::string(reinterpret_cast<char*>(b64), static_cast<size_t>(n));
}

std::string encode_frame(Opcode op, const unsigned char* data, size_t len, bool mask) {
    std::string out;
    out.push_back(static_cast<char>(0x80 | static_cast<uint8_t>(op)));  // FIN always set
    unsigned char mask_key[4] = {0, 0, 0, 0};
    if (mask && RAND_bytes(mask_key, sizeof mask_key) != 1)
        return std::string();

    // Second byte: mask bit OR length encoding (RFC 6455 §5.2).
    const unsigned char b1 = mask ? 0x80 : 0x00;
    if (len < 126) {
        out.push_back(static_cast<char>(b1 | len));
    } else if (len <= 0xFFFF) {
        out.push_back(static_cast<char>(b1 | 126));
        out.push_back(static_cast<char>((len >> 8) & 0xFF));
        out.push_back(static_cast<char>(len & 0xFF));
    } else {
        out.push_back(static_cast<char>(b1 | 127));
        for (int i = 7; i >= 0; --i) {
            out.push_back(static_cast<char>((len >> (i * 8)) & 0xFF));
        }
    }
    if (mask) {
        out.append(reinterpret_cast<const char*>(mask_key), 4);
        for (size_t i = 0; i < len; ++i) {
            out.push_back(static_cast<char>(data[i] ^ mask_key[i % 4]));
        }
    } else {
        out.append(reinterpret_cast<const char*>(data), len);
    }
    return out;
}

bool decode_frame(const unsigned char* buf, size_t len, Frame* out, size_t* consumed) {
    if (!out || !consumed || len < 2)
        return false;
    const uint8_t b0 = buf[0];
    const uint8_t b1 = buf[1];

    out->fin = (b0 & 0x80) != 0;
    // RSV bits must be clear (no extensions negotiated).
    if (b0 & 0x70)
        return false;
    out->opcode = static_cast<Opcode>(b0 & 0x0F);

    const bool masked = (b1 & 0x80) != 0;
    size_t payload_len = b1 & 0x7F;
    size_t hdr = 2;

    if (payload_len == 126) {
        if (len < 4)
            return false;
        payload_len = (static_cast<size_t>(buf[2]) << 8) | buf[3];
        hdr = 4;
    } else if (payload_len == 127) {
        if (len < 10)
            return false;
        payload_len = 0;
        for (int i = 0; i < 8; ++i)
            payload_len = (payload_len << 8) | buf[2 + i];
        hdr = 10;
    }
    if (payload_len > kMaxPayload)
        return false;

    // Control frames: FIN must be set, payload <= 125.
    if ((static_cast<uint8_t>(out->opcode) & 0x08) != 0 && (!out->fin || payload_len > 125))
        return false;

    unsigned char mask_key[4] = {0, 0, 0, 0};
    if (masked) {
        if (len < hdr + 4)
            return false;
        for (int i = 0; i < 4; ++i)
            mask_key[i] = buf[hdr + i];
        hdr += 4;
    }
    if (len < hdr + payload_len)
        return false;  // truncated

    out->payload.resize(payload_len);
    for (size_t i = 0; i < payload_len; ++i) {
        out->payload[i] =
            masked ? static_cast<unsigned char>(buf[hdr + i] ^ mask_key[i % 4]) : buf[hdr + i];
    }
    *consumed = hdr + payload_len;
    return true;
}

long long frame_size(const unsigned char* buf, size_t len) {
    if (len < 2)
        return -1;
    const uint8_t b0 = buf[0];
    const uint8_t b1 = buf[1];
    if (b0 & 0x70)
        return 0;  // reserved bits
    size_t payload_len = b1 & 0x7F;
    size_t hdr = 2;
    if (payload_len == 126) {
        if (len < 4)
            return -1;
        payload_len = (static_cast<size_t>(buf[2]) << 8) | buf[3];
        hdr = 4;
    } else if (payload_len == 127) {
        if (len < 10)
            return -1;
        payload_len = 0;
        for (int i = 0; i < 8; ++i)
            payload_len = (payload_len << 8) | buf[2 + i];
        hdr = 10;
    }
    if (payload_len > kMaxPayload)
        return 0;
    if ((b0 & 0x0F) != 0 && (b0 & 0x0F) >= 0x8 && payload_len > 125)
        return 0;
    if ((b0 & 0x0F) >= 0x8 && !(b0 & 0x80))
        return 0;  // control without FIN
    hdr += (b1 & 0x80) ? 4 : 0;
    if (len < hdr + payload_len)
        return -1;
    return static_cast<long long>(hdr + payload_len);
}

}  // namespace gp::ws