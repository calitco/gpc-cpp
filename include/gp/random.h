// Cryptographically secure random helpers (getrandom(2) with /dev/urandom
// fallback). Used for session tokens, service keys and nonces.
#pragma once

#include <cstdint>
#include <random>
#include <string>
#include <vector>

namespace gp::rand {

// Fill buf with n cryptographically secure random bytes. Throws std::runtime_error
// on failure (never returns zeros silently).
void fill_random(std::vector<unsigned char>& buf);

std::vector<unsigned char> random_bytes(std::size_t n);

// URL-safe base64url encoding without padding.
std::string to_base64url(const unsigned char* data, std::size_t len);
std::string to_base64url(const std::vector<unsigned char>& data);

// Lowercase hex encoding.
std::string to_hex(const unsigned char* data, std::size_t len);
std::string to_hex(const std::vector<unsigned char>& data);

// Constant-time comparison (prevents timing oracles on tokens/keys).
bool constant_time_equals(const void* a, std::size_t alen, const void* b, std::size_t blen);

}  // namespace gp::rand
