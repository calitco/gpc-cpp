// Tests for finding H-3 fixes: secrets via stdin (never argv), 0600 files,
// redacted logging.
#include <fcntl.h>
#include <gp/secret_transport.h>
#include <sys/stat.h>
#include <unistd.h>

#include "test_framework.h"

using namespace gp::secrets;

namespace {
mode_t mode_of(const std::string& path) {
    struct stat st{};
    if (::stat(path.c_str(), &st) != 0)
        return 0;
    return st.st_mode & 0777;
}
std::string read_file(const std::string& path) {
    std::string out;
    std::FILE* f = std::fopen(path.c_str(), "rb");
    if (!f)
        return "";
    char tmp[4096];
    size_t n;
    while ((n = std::fread(tmp, 1, sizeof(tmp), f)) > 0)
        out.append(tmp, n);
    std::fclose(f);
    return out;
}
}  // namespace

TEST(secrets, argv_scan_detects_leaks) {
    CHECK(argv_contains_secret({"--key-password", "hunter2-secret"}, {"hunter2-secret"}));
    CHECK(!argv_contains_secret({"--key-password", "[stdin]"}, {"hunter2-secret"}));
    // Empty secrets are ignored (no accidental whole-argv matches).
    CHECK(!argv_contains_secret({"anything"}, {""}));
}

TEST(secrets, spawn_refuses_secrets_in_argv) {
    std::string err;
    bool ok =
        spawn_with_stdin_secrets("/bin/cat", {"--x", "hunter2-secret"}, {"hunter2-secret"}, &err);
    CHECK(!ok);
    CHECK(err.find("argv") != std::string::npos);
}

TEST(secrets, spawn_delivers_secrets_on_stdin) {
    const std::string out_path = "/tmp/gp_secret_test_out." + std::to_string(::getpid());
    ::unlink(out_path.c_str());
    std::string err;
    bool ok = spawn_with_stdin_secrets("/bin/sh", {"-c", "cat > " + out_path},
                                       {"alpha-secret-value", "beta-secret-value"}, &err);
    if (!ok)
        std::cerr << "spawn error: " << err << std::endl;
    CHECK(ok);
    CHECK_EQ(read_file(out_path), std::string("alpha-secret-value\n"
                                              "beta-secret-value\n"));
    ::unlink(out_path.c_str());
}

TEST(secrets, secret_file_is_0600_even_with_open_umask) {
    mode_t old = umask(0);  // worst-case umask: everything world-readable
    const std::string path = "/tmp/gp_secret_test_key." + std::to_string(::getpid());
    ::unlink(path.c_str());
    bool ok = write_secret_file(path, "0123456789abcdef0123456789abcdef");
    umask(old);
    CHECK(ok);
    CHECK_EQ(mode_of(path), (mode_t)0600);
    ::unlink(path.c_str());

    // O_EXCL: second create without overwrite must fail.
    ok = write_secret_file(path, "data");
    CHECK(ok);
    std::string err;
    CHECK(!write_secret_file(path, "again", false, &err));
    ::unlink(path.c_str());
}

TEST(secrets, log_file_is_0600_even_with_open_umask) {
    mode_t old = umask(0);
    const std::string path = "/tmp/gp_secret_test_log." + std::to_string(::getpid());
    ::unlink(path.c_str());
    int fd = open_log_file_0600(path);
    umask(old);
    CHECK(fd >= 0);
    ::close(fd);
    CHECK_EQ(mode_of(path), (mode_t)0600);
    ::unlink(path.c_str());
}

TEST(secrets, redactor_masks_registered_values) {
    Redactor r;
    r.add_value("topsecretvalue");
    r.add_value("s3ss10n-cookie=abc123");
    CHECK_EQ(r.redact("Auth data: topsecretvalue end"), std::string("Auth data: [REDACTED] end"));
    CHECK_EQ(r.redact("x s3ss10n-cookie=abc123 y s3ss10n-cookie=abc123 z"),
             std::string("x [REDACTED] y [REDACTED] z"));
    // Values shorter than 4 chars are ignored (no over-redaction).
    r.add_value("ab");
    CHECK_EQ(r.redact("ab cd"), std::string("ab cd"));
}

TEST(secrets, redactor_never_leaks_raw_payload) {
    const std::string payload = "globalprotectcallback:CAISz-s3cr3t-payload-XYZ";
    Redactor r;
    r.add_value(payload);
    std::string line = "Failed to decode SAML auth data: bad base64, data: " + payload;
    std::string out = r.redact(line);
    CHECK(out.find(payload) == std::string::npos);
    CHECK(out.find("[REDACTED]") != std::string::npos);
}

int main() {
    return gp::test::Registry::instance().run_all();
}
