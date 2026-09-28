// ChaCha20-Poly1305 AEAD helpers (OpenSSL EVP) — the local service daemon's
// payload cipher, matching the algorithm the Rust gpservice used.
// Wire format per message: 12-byte random nonce || ciphertext || 16-byte tag.
#pragma once

#include <cstddef>
#include <string>
#include <vector>

namespace gp::aead {

constexpr size_t kKeySize = 32;
constexpr size_t kNonceSize = 12;
constexpr size_t kTagSize = 16;

// Seal plaintext: *out = ciphertext || tag (nonce NOT included — the caller
// prepends it on the wire). Empty AAD.
bool seal(const std::vector<unsigned char>& key, const unsigned char nonce[kNonceSize],
          const void* pt, size_t len, std::string* out);

// Open a sealed message: input = ciphertext || tag (nonce separate). Returns
// false on any authentication failure (tampered ciphertext or wrong key) —
// in that case *out is left untouched.
bool open(const std::vector<unsigned char>& key, const unsigned char nonce[kNonceSize],
          const void* ct_tag, size_t len, std::string* out);

}  // namespace gp::aead