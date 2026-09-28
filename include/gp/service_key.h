// Service API key management — fixes finding M-1 (hardcoded all-zero key in
// debug builds). The key is ALWAYS generated from a CSPRNG at startup; there
// is no compile-time fallback constant anywhere. Operators may load their own
// key from a file, but the file must be owner-only (0600) unless they
// explicitly relax that with --allow-insecure-key-file.
#pragma once

#include <string>
#include <vector>

namespace gp::service {

class ServiceKey {
   public:
    static constexpr int kSize = 32;  // ChaCha20-Poly1305 key size, as before

    // Fresh CSPRNG key. Refuses to return an all-zero key (retries).
    static ServiceKey generate();

    // Load a 32-byte key from `path`. Fails if: file unreadable, wrong length,
    // all zeros, or group/other permission bits are set and
    // allow_insecure_permissions is false.
    bool load_from_file(const std::string& path, bool allow_insecure_permissions,
                        std::string* err = nullptr);

    const std::vector<unsigned char>& bytes() const { return bytes_; }
    bool valid() const { return bytes_.size() == kSize; }

    // Lowercase hex (for logs — the key itself is not a display secret in the
    // old design either, but hex keeps it copy-paste safe).
    std::string hex() const;

   private:
    std::vector<unsigned char> bytes_;
};

}  // namespace gp::service
