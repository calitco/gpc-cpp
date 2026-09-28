#include "gp/service_key.h"

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <sstream>
#include <stdexcept>

#include "gp/random.h"

namespace gp::service {

ServiceKey ServiceKey::generate() {
    // No hardcoded fallback exists (M-1): the old code shipped a 32-byte zero
    // constant for debug builds. Here the key is always fresh CSPRNG output,
    // and an all-zero result (astronomically unlikely) is rejected anyway.
    for (int attempt = 0; attempt < 8; ++attempt) {
        auto b = rand::random_bytes(kSize);
        bool all_zero = true;
        for (unsigned char c : b)
            all_zero = all_zero && (c == 0);
        if (!all_zero) {
            ServiceKey k;
            k.bytes_ = std::move(b);
            return k;
        }
    }
    throw std::runtime_error("CSPRNG produced only zero blocks (hardware fault?)");
}

bool ServiceKey::load_from_file(const std::string& path, bool allow_insecure_permissions,
                                std::string* err) {
    struct stat st{};
    if (::stat(path.c_str(), &st) != 0 || !S_ISREG(st.st_mode)) {
        if (err)
            *err = "cannot stat key file: " + path;
        return false;
    }
    // World/group-readable key files are refused by default. The old design's
    // API key protected the whole service API; a shared file defeats that.
    if ((st.st_mode & 077) != 0 && !allow_insecure_permissions) {
        std::ostringstream oss;
        oss << "key file has group/other permission bits (mode 0" << std::oct << st.st_mode
            << std::dec << ")";
        if (err)
            *err = oss.str() + "; fix with chmod 600 or pass --allow-insecure-key-file";
        return false;
    }

    int fd = ::open(path.c_str(), O_RDONLY);
    if (fd < 0) {
        if (err)
            *err = "cannot open key file: " + path;
        return false;
    }
    std::vector<unsigned char> buf(kSize);
    std::size_t got = 0;
    while (got < kSize) {
        ssize_t n = ::read(fd, buf.data() + got, kSize - got);
        if (n <= 0)
            break;
        got += static_cast<std::size_t>(n);
    }
    ::close(fd);
    if (got != kSize) {
        if (err)
            *err = "key file must be exactly " + std::to_string(kSize) + " bytes (got " +
                   std::to_string(got) + ")";
        return false;
    }
    bool all_zero = true;
    for (unsigned char c : buf)
        all_zero = all_zero && (c == 0);
    if (all_zero) {
        if (err)
            *err = "refusing all-zero key file";
        return false;
    }
    bytes_ = std::move(buf);
    return true;
}

std::string ServiceKey::hex() const {
    return rand::to_hex(bytes_);
}

}  // namespace gp::service
