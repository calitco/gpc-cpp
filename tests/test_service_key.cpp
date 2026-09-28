// Tests for finding M-1 fix: the service key is always fresh CSPRNG output —
// no hardcoded zero fallback — and operator-supplied key files must be 0600.
#include <fcntl.h>
#include <gp/service_key.h>
#include <sys/stat.h>
#include <unistd.h>

#include "test_framework.h"

using gp::service::ServiceKey;

namespace {
void write_raw(const std::string& path, const void* data, size_t len, mode_t mode) {
    int fd = ::open(path.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0600);
    REQUIRE(fd >= 0);
    ::fchmod(fd, mode);
    ::write(fd, data, len);
    ::close(fd);
}
}  // namespace

TEST(servicekey, generate_is_nonzero_and_unique) {
    auto a = ServiceKey::generate();
    auto b = ServiceKey::generate();
    CHECK(a.valid());
    CHECK_EQ(a.bytes().size(), (size_t)ServiceKey::kSize);
    bool all_zero = true;
    for (unsigned char c : a.bytes())
        all_zero = all_zero && (c == 0);
    CHECK(!all_zero);
    CHECK(a.bytes() != b.bytes());
    CHECK_EQ(a.hex().size(), (size_t)64);
}

TEST(servicekey, load_accepts_0600_file) {
    const std::string path = "/tmp/gp_key_test." + std::to_string(::getpid());
    unsigned char key[32];
    for (int i = 0; i < 32; ++i)
        key[i] = static_cast<unsigned char>(i + 1);
    write_raw(path, key, sizeof(key), 0600);

    ServiceKey k;
    std::string err;
    CHECK(k.load_from_file(path, false, &err));
    CHECK(k.valid());
    ::unlink(path.c_str());
}

TEST(servicekey, load_refuses_group_readable_file_by_default) {
    const std::string path = "/tmp/gp_key_test_gr." + std::to_string(::getpid());
    unsigned char key[32];
    for (int i = 0; i < 32; ++i)
        key[i] = static_cast<unsigned char>(i + 1);
    write_raw(path, key, sizeof(key), 0644);

    ServiceKey k;
    std::string err;
    CHECK(!k.load_from_file(path, false, &err));
    CHECK(err.find("permission bits") != std::string::npos);

    // Explicit opt-in switch allows it.
    CHECK(k.load_from_file(path, true, &err));
    ::unlink(path.c_str());
}

TEST(servicekey, load_refuses_wrong_length_and_all_zero) {
    const std::string path = "/tmp/gp_key_test_bad." + std::to_string(::getpid());
    unsigned char short_key[31] = {0};
    write_raw(path, short_key, sizeof(short_key), 0600);
    ServiceKey k;
    std::string err;
    CHECK(!k.load_from_file(path, false, &err));

    unsigned char zeros[32] = {0};
    write_raw(path, zeros, sizeof(zeros), 0600);
    CHECK(!k.load_from_file(path, false, &err));
    ::unlink(path.c_str());
}

int main() {
    return gp::test::Registry::instance().run_all();
}