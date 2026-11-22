#include "aes_sea.hpp"
#include "process_trace.hpp"
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <cstring>
#include <stdexcept>

namespace cyb3r {

// Internal helper – AES-256-CBC encrypt with a random IV prepended
static std::vector<uint8_t> aes256_cbc_encrypt(const Bytes32& key,
                                               const std::vector<uint8_t>& pt) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("EVP_CIPHER_CTX_new failed");

    Bytes32 iv{};
    if (RAND_bytes(iv.data(), 32) != 1) {
        // fallback deterministic IV from key for pure determinism if needed
        std::memcpy(iv.data(), key.data(), 16);
    }

    std::vector<uint8_t> ct(pt.size() + 32 + 16); // IV + possible padding
    int len = 0, total = 0;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key.data(), iv.data()) != 1)
        throw std::runtime_error("EncryptInit failed");

    // Prepend IV
    std::memcpy(ct.data(), iv.data(), 16);
    total = 16;

    if (EVP_EncryptUpdate(ctx, ct.data() + total, &len, pt.data(), static_cast<int>(pt.size())) != 1)
        throw std::runtime_error("EncryptUpdate failed");
    total += len;

    if (EVP_EncryptFinal_ex(ctx, ct.data() + total, &len) != 1)
        throw std::runtime_error("EncryptFinal failed");
    total += len;

    ct.resize(total);
    EVP_CIPHER_CTX_free(ctx);
    return ct;
}

static std::vector<uint8_t> aes256_cbc_decrypt(const Bytes32& key,
                                               const std::vector<uint8_t>& ct) {
    if (ct.size() < 16) throw std::runtime_error("ciphertext too short");

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("EVP_CIPHER_CTX_new failed");

    const uint8_t* iv = ct.data();
    const uint8_t* data = ct.data() + 16;
    int data_len = static_cast<int>(ct.size() - 16);

    std::vector<uint8_t> pt(ct.size());
    int len = 0, total = 0;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key.data(), iv) != 1)
        throw std::runtime_error("DecryptInit failed");

    if (EVP_DecryptUpdate(ctx, pt.data(), &len, data, data_len) != 1)
        throw std::runtime_error("DecryptUpdate failed");
    total = len;

    if (EVP_DecryptFinal_ex(ctx, pt.data() + total, &len) != 1)
        throw std::runtime_error("DecryptFinal failed (bad key or padding)");
    total += len;

    pt.resize(total);
    EVP_CIPHER_CTX_free(ctx);
    return pt;
}

Bytes64 AES_SEA::derive_512(const Bytes32& half_a, const Bytes32& half_b) {
    // Patent-inspired construction:
    // 1. Concatenate the two 256-bit halves → 512-bit material
    // 2. Run a series of AES-based mixing rounds (simulated "10-bit rounds")
    // 3. Produce a final 512-bit validation key

    Bytes64 material{};
    std::memcpy(material.data(),      half_a.data(), 32);
    std::memcpy(material.data() + 32, half_b.data(), 32);

    // Simple multi-round mixing using SHA-256 (acts as a stand-in for the
    // patent's AES-SEA round function while remaining pure software)
    for (int round = 0; round < 10; ++round) {
        Bytes32 left{}, right{};
        std::memcpy(left.data(),  material.data(),      32);
        std::memcpy(right.data(), material.data() + 32, 32);

        // Mix: SHA256(left || right || round)
        uint8_t buf[65];
        std::memcpy(buf, left.data(), 32);
        std::memcpy(buf + 32, right.data(), 32);
        buf[64] = static_cast<uint8_t>(round);

        Bytes32 hash{};
        SHA256(buf, 65, hash.data());

        // Feed back into the 512-bit state
        for (size_t i = 0; i < 32; ++i) {
            material[i]      ^= hash[i];
            material[i + 32] ^= hash[31 - i];
        }
    }

    return material;
}

std::vector<uint8_t> AES_SEA::encrypt(const Bytes32& key,
                                      const std::vector<uint8_t>& plaintext) {
    return aes256_cbc_encrypt(key, plaintext);
}

std::vector<uint8_t> AES_SEA::decrypt(const Bytes32& key,
                                      const std::vector<uint8_t>& ciphertext) {
    return aes256_cbc_decrypt(key, ciphertext);
}

Bytes32 AES_SEA::session_key_from_512(const Bytes64& master, uint64_t nonce) {
    // Derive a 256-bit session key: SHA256(master || nonce)
    uint8_t buf[72];
    std::memcpy(buf, master.data(), 64);
    for (int i = 0; i < 8; ++i)
        buf[64 + i] = static_cast<uint8_t>((nonce >> (i * 8)) & 0xFF);

    Bytes32 sk{};
    SHA256(buf, 72, sk.data());
    return sk;
}

} // namespace cyb3r
