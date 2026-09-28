#include "gp/random.h"

#include <cerrno>
#include <cstdio>
#include <stdexcept>
#include <string>

#ifdef __linux__
#include <sys/random.h>
#endif

namespace gp::rand {

void fill_random(std::vector<unsigned char>& buf) {
    if (buf.empty())
        return;
#ifdef __linux__
    std::size_t got = 0;
    while (got < buf.size()) {
        ssize_t n = getrandom(buf.data() + got, buf.size() - got, 0);
        if (n > 0) {
            got += static_cast<std::size_t>(n);
            continue;
        }
        if (n < 0 && errno != EINTR)
            break;  // fall through to /dev/urandom
    }
    if (got == buf.size())
        return;
#endif
    std::FILE* f = std::fopen("/dev/urandom", "rb");
    if (!f)
        throw std::runtime_error("cannot open /dev/urandom");
    if (std::fread(buf.data(), 1, buf.size(), f) != buf.size()) {
        std::fclose(f);
        throw std::runtime_error("short read from /dev/urandom");
    }
    std::fclose(f);
}

std::vector<unsigned char> random_bytes(std::size_t n) {
    std::vector<unsigned char> buf(n);
    fill_random(buf);
    return buf;
}

namespace {
const char kB64Url[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
}

std::string to_base64url(const unsigned char* data, std::size_t len) {
    std::string out;
    out.reserve((len + 2) / 3 * 4);
    std::size_t i = 0;
    while (i + 3 <= len) {
        unsigned v = (data[i] << 16) | (data[i + 1] << 8) | data[i + 2];
        out += kB64Url[(v >> 18) & 63];
        out += kB64Url[(v >> 12) & 63];
        out += kB64Url[(v >> 6) & 63];
        out += kB64Url[v & 63];
        i += 3;
    }
    if (len - i == 1) {
        unsigned v = data[i] << 16;
        out += kB64Url[(v >> 18) & 63];
        out += kB64Url[(v >> 12) & 63];
    } else if (len - i == 2) {
        unsigned v = (data[i] << 16) | (data[i + 1] << 8);
        out += kB64Url[(v >> 18) & 63];
        out += kB64Url[(v >> 12) & 63];
        out += kB64Url[(v >> 6) & 63];
    }
    return out;  // no padding: URL-safe by construction
}

std::string to_base64url(const std::vector<unsigned char>& data) {
    return to_base64url(data.data(), data.size());
}

std::string to_hex(const unsigned char* data, std::size_t len) {
    static const char* digits = "0123456789abcdef";
    std::string out;
    out.reserve(len * 2);
    for (std::size_t i = 0; i < len; ++i) {
        out += digits[data[i] >> 4];
        out += digits[data[i] & 0xf];
    }
    return out;
}

std::string to_hex(const std::vector<unsigned char>& data) {
    return to_hex(data.data(), data.size());
}

bool constant_time_equals(const void* a, std::size_t alen, const void* b, std::size_t blen) {
    if (alen != blen)
        return false;
    const auto* pa = static_cast<const unsigned char*>(a);
    const auto* pb = static_cast<const unsigned char*>(b);
    unsigned char diff = 0;
    for (std::size_t i = 0; i < alen; ++i)
        diff |= pa[i] ^ pb[i];
    return diff == 0;
}

}  // namespace gp::rand
