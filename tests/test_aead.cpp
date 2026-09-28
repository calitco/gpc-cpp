// Tests for gp::aead — ChaCha20-Poly1305 seal/open (the daemon's payload cipher).
#include <string>
#include <vector>

#include "gp/aead.h"
#include "test_framework.h"

using namespace gp::aead;

namespace {

std::vector<unsigned char> make_key(unsigned seed) {
    std::vector<unsigned char> key(kKeySize);
    for (size_t i = 0; i < key.size(); ++i)
        key[i] = static_cast<unsigned char>(seed * 31 + i * 7 + 1);
    return key;
}

void fill_nonce(unsigned char nonce[kNonceSize], unsigned seed) {
    for (size_t i = 0; i < kNonceSize; ++i)
        nonce[i] = static_cast<unsigned char>(seed * 13 + i * 5 + 2);
}

}  // namespace

TEST(aead, seal_open_roundtrip) {
    auto key = make_key(1);
    unsigned char nonce[kNonceSize];
    fill_nonce(nonce, 7);
    const std::string pt = "the tunnel payload";
    std::string ct_tag;
    REQUIRE(seal(key, nonce, pt.data(), pt.size(), &ct_tag));
    CHECK_EQ(ct_tag.size(), pt.size() + kTagSize);

    std::string recovered;
    CHECK(open(key, nonce, ct_tag.data(), ct_tag.size(), &recovered));
    CHECK_EQ(recovered, pt);
}

TEST(aead, empty_plaintext_roundtrip) {
    auto key = make_key(2);
    unsigned char nonce[kNonceSize];
    fill_nonce(nonce, 8);
    std::string ct_tag;
    REQUIRE(seal(key, nonce, nullptr, 0, &ct_tag));
    CHECK_EQ(ct_tag.size(), kTagSize);

    std::string recovered = "sentinel";
    CHECK(open(key, nonce, ct_tag.data(), ct_tag.size(), &recovered));
    CHECK(recovered.empty());
}

TEST(aead, deterministic_per_nonce_different_across_nonces) {
    auto key = make_key(3);
    const std::string pt = "same plaintext";
    unsigned char n1[kNonceSize], n2[kNonceSize];
    fill_nonce(n1, 1);
    fill_nonce(n2, 2);

    std::string ct_a, ct_b, ct_c;
    REQUIRE(seal(key, n1, pt.data(), pt.size(), &ct_a));
    REQUIRE(seal(key, n1, pt.data(), pt.size(), &ct_b));
    REQUIRE(seal(key, n2, pt.data(), pt.size(), &ct_c));
    CHECK(ct_a == ct_b);  // same key + nonce + plaintext => identical ciphertext
    CHECK(ct_a != ct_c);  // different nonce => different ciphertext
}

TEST(aead, tampered_ciphertext_rejected) {
    auto key = make_key(4);
    unsigned char nonce[kNonceSize];
    fill_nonce(nonce, 9);
    const std::string pt = "tamper with me";
    std::string ct_tag;
    REQUIRE(seal(key, nonce, pt.data(), pt.size(), &ct_tag));

    ct_tag[0] ^= 0x01;  // flip one ciphertext bit
    std::string recovered = "sentinel";
    CHECK(!open(key, nonce, ct_tag.data(), ct_tag.size(), &recovered));
    CHECK_EQ(recovered, "sentinel");  // untouched on failure
}

TEST(aead, tampered_tag_rejected) {
    auto key = make_key(5);
    unsigned char nonce[kNonceSize];
    fill_nonce(nonce, 10);
    const std::string pt = "tag integrity";
    std::string ct_tag;
    REQUIRE(seal(key, nonce, pt.data(), pt.size(), &ct_tag));

    ct_tag.back() ^= 0x80;  // flip one tag bit
    std::string recovered;
    CHECK(!open(key, nonce, ct_tag.data(), ct_tag.size(), &recovered));
}

TEST(aead, wrong_key_rejected) {
    auto key = make_key(6);
    auto other = make_key(7);
    unsigned char nonce[kNonceSize];
    fill_nonce(nonce, 11);
    const std::string pt = "key separation";
    std::string ct_tag;
    REQUIRE(seal(key, nonce, pt.data(), pt.size(), &ct_tag));

    std::string recovered;
    CHECK(!open(other, nonce, ct_tag.data(), ct_tag.size(), &recovered));
}

TEST(aead, wrong_nonce_rejected) {
    auto key = make_key(8);
    unsigned char n1[kNonceSize], n2[kNonceSize];
    fill_nonce(n1, 12);
    fill_nonce(n2, 13);
    const std::string pt = "nonce binding";
    std::string ct_tag;
    REQUIRE(seal(key, n1, pt.data(), pt.size(), &ct_tag));

    std::string recovered;
    CHECK(!open(key, n2, ct_tag.data(), ct_tag.size(), &recovered));
}

TEST(aead, input_shorter_than_tag_rejected) {
    auto key = make_key(9);
    unsigned char nonce[kNonceSize];
    fill_nonce(nonce, 14);
    std::string recovered;
    CHECK(!open(key, nonce, "short", 5, &recovered));
    CHECK(!open(key, nonce, nullptr, 0, &recovered));
}

TEST(aead, malformed_key_size_rejected) {
    unsigned char nonce[kNonceSize];
    fill_nonce(nonce, 15);
    std::vector<unsigned char> short_key(16, 0xAA);
    std::string out;
    CHECK(!seal(short_key, nonce, "x", 1, &out));
    CHECK(!open(short_key, nonce, "y", kTagSize + 1, &out));
}

int main() {
    return gp::test::Registry::instance().run_all();
}
