// ChaCha20-Poly1305 via OpenSSL EVP. See include/gp/aead.h.
#include "gp/aead.h"

#include <openssl/evp.h>

namespace gp::aead {

namespace {

bool check_key(const std::vector<unsigned char>& key) {
    return key.size() == kKeySize;
}

}  // namespace

bool seal(const std::vector<unsigned char>& key, const unsigned char nonce[kNonceSize],
          const void* pt, size_t len, std::string* out) {
    if (!check_key(key) || !out)
        return false;
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        return false;
    bool ok = false;
    do {
        if (EVP_EncryptInit_ex(ctx, EVP_chacha20_poly1305(), nullptr, nullptr, nullptr) != 1)
            break;
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, static_cast<int>(kNonceSize),
                                nullptr) != 1)
            break;
        if (EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce) != 1)
            break;

        std::string ct(len, '\0');
        int outlen = 0;
        if (len > 0 &&
            EVP_EncryptUpdate(ctx, reinterpret_cast<unsigned char*>(ct.data()), &outlen,
                              static_cast<const unsigned char*>(pt), static_cast<int>(len)) != 1) {
            break;
        }
        ct.resize(static_cast<size_t>(outlen));
        int finlen = 0;
        if (EVP_EncryptFinal_ex(ctx, reinterpret_cast<unsigned char*>(ct.data()) + ct.size(),
                                &finlen) != 1) {
            break;
        }
        ct.resize(ct.size() + static_cast<size_t>(finlen));

        unsigned char tag[kTagSize];
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, static_cast<int>(kTagSize), tag) != 1) {
            break;
        }
        out->append(reinterpret_cast<const char*>(tag), kTagSize);
        *out = ct + *out;
        ok = true;
    } while (false);
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

bool open(const std::vector<unsigned char>& key, const unsigned char nonce[kNonceSize],
          const void* ct_tag, size_t len, std::string* out) {
    if (!check_key(key) || !out || len < kTagSize)
        return false;
    const auto* in = static_cast<const unsigned char*>(ct_tag);
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        return false;
    bool ok = false;
    do {
        size_t ct_len = len - kTagSize;
        if (EVP_DecryptInit_ex(ctx, EVP_chacha20_poly1305(), nullptr, nullptr, nullptr) != 1)
            break;
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, static_cast<int>(kNonceSize),
                                nullptr) != 1)
            break;
        if (EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce) != 1)
            break;

        std::string pt(ct_len, '\0');
        int outlen = 0;
        if (ct_len > 0 && EVP_DecryptUpdate(ctx, reinterpret_cast<unsigned char*>(pt.data()),
                                            &outlen, in, static_cast<int>(ct_len)) != 1) {
            break;
        }
        pt.resize(static_cast<size_t>(outlen));
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, static_cast<int>(kTagSize),
                                const_cast<unsigned char*>(in + ct_len)) != 1) {
            break;
        }
        int finlen = 0;
        // DecryptFinal verifies the tag; -1 means authentication failure.
        if (EVP_DecryptFinal_ex(ctx, reinterpret_cast<unsigned char*>(pt.data()) + pt.size(),
                                &finlen) != 1) {
            break;
        }
        pt.resize(pt.size() + static_cast<size_t>(finlen));
        *out = std::move(pt);
        ok = true;
    } while (false);
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

}  // namespace gp::aead