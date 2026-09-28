// Test helper: generate throwaway X.509 certificates in memory (EC P-256,
// fast) for the certificate policy tests.
#pragma once

#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <chrono>
#include <string>
#include <vector>

namespace gp::certtest {

struct TestCert {
    std::vector<unsigned char> der;
    EVP_PKEY* key = nullptr;
    X509* cert = nullptr;

    TestCert() = default;
    ~TestCert() {
        if (key)
            EVP_PKEY_free(key);
        if (cert)
            X509_free(cert);
    }
    TestCert(const TestCert&) = delete;
    TestCert& operator=(const TestCert&) = delete;
};

inline std::chrono::system_clock::time_point epoch() {
    return std::chrono::system_clock::from_time_t(0);
}

inline ASN1_TIME* make_time(std::chrono::system_clock::time_point tp) {
    time_t t = std::chrono::system_clock::to_time_t(tp);
    return ASN1_TIME_set(nullptr, t);
}

// NOTE: this build's EC key generation is broken (provider keymgmt failure),
// so tests use explicit RSA-2048 keys instead.
inline EVP_PKEY* new_key() {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_name(nullptr, "RSA", nullptr);
    if (!ctx)
        return nullptr;
    EVP_PKEY* key = nullptr;
    bool ok = EVP_PKEY_keygen_init(ctx) == 1;
    if (ok) {
        int bits = 2048;
        OSSL_PARAM params[2] = {OSSL_PARAM_construct_int(OSSL_PKEY_PARAM_RSA_BITS, &bits),
                                OSSL_PARAM_END};
        ok = EVP_PKEY_CTX_set_params(ctx, params) == 1 && EVP_PKEY_keygen(ctx, &key) == 1;
    }
    EVP_PKEY_CTX_free(ctx);
    return key;
}

inline void set_cn(X509_NAME* nm, const std::string& cn) {
    X509_NAME_add_entry_by_txt(nm, "CN", MBSTRING_ASC,
                               reinterpret_cast<const unsigned char*>(cn.c_str()), -1, -1, 0);
}

// Self-signed CA (basicConstraints CA:TRUE, keyCertSign). Out-parameter
// style: no move/return of the OpenSSL-owning struct.
inline void make_ca(TestCert& c, const std::string& name) {
    c.key = new_key();
    c.cert = X509_new();
    X509_set_version(c.cert, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(c.cert), 1);
    auto* subj = X509_NAME_new();
    set_cn(subj, name);
    X509_set_subject_name(c.cert, subj);
    X509_set_issuer_name(c.cert, subj);
    X509_NAME_free(subj);

    auto now = std::chrono::system_clock::now();
    ASN1_TIME* nb = make_time(now - std::chrono::hours(1));
    ASN1_TIME* na = make_time(now + std::chrono::hours(24 * 30));
    X509_set1_notBefore(c.cert, nb);
    X509_set1_notAfter(c.cert, na);
    ASN1_STRING_free(nb);
    ASN1_STRING_free(na);

    X509_set_pubkey(c.cert, c.key);

    X509V3_CTX vctx;
    X509V3_set_ctx_nodb(&vctx);
    X509V3_set_ctx(&vctx, c.cert, nullptr, nullptr, nullptr, 0);
    X509_EXTENSION* bc =
        X509V3_EXT_conf_nid(nullptr, &vctx, NID_basic_constraints, "critical,CA:TRUE");
    X509_add_ext(c.cert, bc, -1);
    X509_EXTENSION_free(bc);
    X509_EXTENSION* ku =
        X509V3_EXT_conf_nid(nullptr, &vctx, NID_key_usage, "critical,keyCertSign,cRLSign");
    X509_add_ext(c.cert, ku, -1);
    X509_EXTENSION_free(ku);

    X509_sign(c.cert, c.key, EVP_sha256());

    unsigned char* der = nullptr;
    int len = i2d_X509(c.cert, &der);
    c.der.assign(der, der + len);
    OPENSSL_free(der);
}

// Leaf signed by `ca`. `sans` are DNS names. Optional explicit validity.
inline void make_leaf(TestCert& c, const TestCert& ca, const std::string& cn,
                      const std::vector<std::string>& sans,
                      std::chrono::system_clock::time_point not_before = {},
                      std::chrono::system_clock::time_point not_after = {}) {
    c.key = new_key();
    c.cert = X509_new();
    X509_set_version(c.cert, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(c.cert), 42);

    auto* subj = X509_NAME_new();
    set_cn(subj, cn);
    X509_set_subject_name(c.cert, subj);
    X509_NAME_free(subj);
    auto* issuer = X509_NAME_dup(X509_get_subject_name(ca.cert));
    X509_set_issuer_name(c.cert, issuer);
    X509_NAME_free(issuer);

    auto now = std::chrono::system_clock::now();
    ASN1_TIME* nb = make_time(not_before == epoch() ? now - std::chrono::hours(1) : not_before);
    ASN1_TIME* na = make_time(not_after == epoch() ? now + std::chrono::hours(24) : not_after);
    X509_set1_notBefore(c.cert, nb);
    X509_set1_notAfter(c.cert, na);
    ASN1_STRING_free(nb);
    ASN1_STRING_free(na);

    X509_set_pubkey(c.cert, c.key);

    if (!sans.empty()) {
        std::string san_value;
        for (size_t i = 0; i < sans.size(); ++i) {
            if (i)
                san_value += ",";
            san_value += "DNS:" + sans[i];
        }
        X509V3_CTX vctx;
        X509V3_set_ctx_nodb(&vctx);
        X509V3_set_ctx(&vctx, c.cert, nullptr, nullptr, nullptr, 0);
        X509_EXTENSION* san =
            X509V3_EXT_conf_nid(nullptr, &vctx, NID_subject_alt_name, san_value.c_str());
        X509_add_ext(c.cert, san, -1);
        X509_EXTENSION_free(san);
    }

    X509_sign(c.cert, ca.key, EVP_sha256());

    unsigned char* der = nullptr;
    int len = i2d_X509(c.cert, &der);
    c.der.assign(der, der + len);
    OPENSSL_free(der);
}

// Build a DER-encoded CRL issued by `ca`, revoking the given serial numbers.
// Returns false (and leaves *out_der untouched) on any OpenSSL failure.
//
// NOTE: this build's X509_CRL_sign() is broken (returns 0 without raising an
// error — same class of provider issue as the broken EC keygen noted above),
// so the CRL is assembled as raw DER here and the TBS is signed directly with
// EVP_DigestSign (which works). The result is re-parsed with d2i_X509_CRL,
// so downstream code sees a normal X509_CRL object.
// DER helpers for make_crl() (inline: this header is shared by several TUs).

inline void der_len(std::string& out, size_t n) {
    if (n < 128) {
        out += static_cast<char>(n);
    } else if (n < 256) {
        out += '\x81';
        out += static_cast<char>(n);
    } else {
        out += '\x82';
        out += static_cast<char>(n >> 8);
        out += static_cast<char>(n & 0xff);
    }
}

inline void der_tlv(std::string& out, unsigned char tag, const std::string& content) {
    out += static_cast<char>(tag);
    der_len(out, content.size());
    out += content;
}

inline std::string der_integer(long value) {
    // Minimal non-negative DER INTEGER (test serials are small).
    std::string mag;
    do {
        mag.insert(mag.begin(), static_cast<char>(value & 0xff));
        value >>= 8;
    } while (value > 0);
    if (static_cast<unsigned char>(mag.front()) & 0x80)
        mag.insert(mag.begin(), '\x00');  // keep it positive
    std::string out;
    der_tlv(out, 0x02, mag);
    return out;
}

inline std::string der_asn1_time(time_t t) {
    ASN1_TIME* tm = ASN1_TIME_set(nullptr, t);
    if (!tm)
        return "";
    unsigned char* p = nullptr;
    int n = i2d_ASN1_TIME(tm, &p);
    std::string out;
    if (n > 0)
        out.assign(reinterpret_cast<char*>(p), static_cast<size_t>(n));
    OPENSSL_free(p);
    ASN1_STRING_free(tm);
    return out;
}

inline bool make_crl(const TestCert& ca, const std::vector<long>& revoked_serials,
                     std::vector<unsigned char>* out_der) {
    // sha256WithRSAEncryption AlgorithmIdentifier (OID 1.2.840.113549.1.1.11 + NULL).
    static const unsigned char kSha256RsaAlg[] = {0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
                                                  0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00};
    // NOTE: explicit length — the array ends in a 0x00 byte and must never be
    // handled with C-string semantics.
    const std::string alg_id(reinterpret_cast<const char*>(kSha256RsaAlg), sizeof kSha256RsaAlg);

    // Issuer = CA subject name.
    unsigned char* p = nullptr;
    int n = i2d_X509_NAME(X509_get_subject_name(ca.cert), &p);
    if (n <= 0)
        return false;
    std::string issuer(reinterpret_cast<char*>(p), static_cast<size_t>(n));
    OPENSSL_free(p);

    time_t now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    std::string last_update = der_asn1_time(now - 3600);
    std::string next_update = der_asn1_time(now + 7 * 86400);
    if (last_update.empty() || next_update.empty())
        return false;

    // Revoked entries: SEQUENCE { INTEGER serialNumber, Time revocationDate }.
    std::string revoked_entries;
    for (long serial : revoked_serials) {
        std::string entry_time = der_asn1_time(now);
        if (entry_time.empty())
            return false;
        std::string entry_inner = der_integer(serial) + entry_time;
        std::string entry;
        der_tlv(entry, 0x30, entry_inner);
        revoked_entries += entry;
    }

    // TBSCertificateList: version(=1 => v2), signature alg, issuer, times, revoked.
    std::string tbs_inner = der_integer(1) + alg_id + issuer + last_update + next_update;
    if (!revoked_entries.empty()) {
        std::string rev_seq;
        der_tlv(rev_seq, 0x30, revoked_entries);
        tbs_inner += rev_seq;
    }
    std::string tbs;
    der_tlv(tbs, 0x30, tbs_inner);

    // Sign the TBS with the CA key (RSA-SHA256).
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx)
        return false;
    size_t sig_len = 0;
    const unsigned char* tbs_bytes = reinterpret_cast<const unsigned char*>(tbs.data());
    bool ok = EVP_DigestSignInit(ctx, nullptr, EVP_sha256(), nullptr, ca.key) == 1 &&
              EVP_DigestSign(ctx, nullptr, &sig_len, tbs_bytes, tbs.size()) == 1;
    std::string sig(sig_len, '\0');
    if (ok) {
        ok = EVP_DigestSign(ctx, reinterpret_cast<unsigned char*>(sig.data()), &sig_len, tbs_bytes,
                            tbs.size()) == 1;
        sig.resize(sig_len);
    }
    EVP_MD_CTX_free(ctx);
    if (!ok || sig.empty())
        return false;

    // BIT STRING signature (0 unused bits).
    std::string bitstr_inner = std::string(1, '\x00') + sig;
    std::string bitstr;
    der_tlv(bitstr, 0x03, bitstr_inner);

    // CertificateList ::= SEQUENCE { tbsCertificateList, signatureAlgorithm, signature }
    std::string crl_inner = tbs + alg_id + bitstr;
    std::string crl_der;
    der_tlv(crl_der, 0x30, crl_inner);

    // Re-parse so callers get a normal X509_CRL (and the signature is checked by
    // any store that uses this CRL).
    const unsigned char* pp = reinterpret_cast<const unsigned char*>(crl_der.data());
    X509_CRL* crl = d2i_X509_CRL(nullptr, &pp, static_cast<long>(crl_der.size()));
    if (!crl)
        return false;
    bool parsed_ok = X509_CRL_get_signature_nid(crl) == NID_sha256WithRSAEncryption;
    unsigned char* out_p = nullptr;
    int out_len = parsed_ok ? i2d_X509_CRL(crl, &out_p) : -1;
    X509_CRL_free(crl);
    if (out_len <= 0)
        return false;
    out_der->assign(out_p, out_p + out_len);
    OPENSSL_free(out_p);
    return true;
}

// Write a CA cert as PEM to a temp file; returns the path (caller unlinks).
inline std::string write_ca_pem(const TestCert& ca, const std::string& path) {
    BIO* bio = BIO_new_file(path.c_str(), "w");
    PEM_write_bio_X509(bio, ca.cert);
    BIO_free(bio);
    return path;
}

// Write CRLs (DER list) as a PEM bundle to `path`; returns the path.
inline std::string write_crl_pem(const std::vector<std::vector<unsigned char>>& crls,
                                 const std::string& path) {
    BIO* bio = BIO_new_file(path.c_str(), "w");
    if (bio) {
        for (const auto& der : crls) {
            const unsigned char* p = der.data();
            X509_CRL* crl = d2i_X509_CRL(nullptr, &p, static_cast<long>(der.size()));
            if (crl) {
                PEM_write_bio_X509_CRL(bio, crl);
                X509_CRL_free(crl);
            }
        }
        BIO_free(bio);
    }
    return path;
}

}  // namespace gp::certtest
