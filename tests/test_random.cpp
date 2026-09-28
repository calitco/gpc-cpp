#include <gp/random.h>

#include "test_framework.h"

using namespace gp::rand;

TEST(random, bytes_are_random_and_sized) {
    auto a = random_bytes(32);
    auto b = random_bytes(32);
    CHECK(a.size() == 32);
    CHECK(b.size() == 32);
    CHECK(a != b);  // collision probability ~2^-256

    auto empty = random_bytes(0);
    CHECK(empty.empty());
}

TEST(random, hex_encoding) {
    std::vector<unsigned char> v{0x00, 0xff, 0x10, 0xab};
    CHECK_EQ(to_hex(v), std::string("00ff10ab"));
    CHECK(to_hex(v).size() == 8);
}

TEST(random, base64url_is_url_safe) {
    for (int i = 0; i < 256; ++i) {
        auto v = random_bytes(32);
        std::string enc = to_base64url(v);
        CHECK(!enc.empty());
        for (char c : enc) {
            CHECK(c != '+' && c != '/' && c != '=');
        }
    }
}

TEST(random, constant_time_equals) {
    const char* a = "abcdef";
    const char* b = "abcdef";
    const char* c = "abcXef";
    const char* d = "abcde";
    CHECK(constant_time_equals(a, 6, b, 6));
    CHECK(!constant_time_equals(a, 6, c, 6));
    CHECK(!constant_time_equals(a, 6, d, 5));  // different lengths
}

int main() {
    return gp::test::Registry::instance().run_all();
}
