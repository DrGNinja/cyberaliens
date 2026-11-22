#pragma once
#include "common.hpp"

namespace cyb3r {

// Lightweight AES-256 simulation of the patent's AES-SEA key construction.
// We use OpenSSL AES-256 for correctness while keeping the high-level flow
// (two 256-bit halves → combined 512-bit validation key via rounds).

class AES_SEA {
public:
    // Derive a 512-bit combined validation key from two 256-bit halves
    // following the patent spirit: 10-bit style mixing rounds + AES.
    static Bytes64 derive_512(const Bytes32& half_a, const Bytes32& half_b);

    // Encrypt / decrypt a payload under a 256-bit session key (AES-256-CBC style)
    static std::vector<uint8_t> encrypt(const Bytes32& key,
                                        const std::vector<uint8_t>& plaintext);
    static std::vector<uint8_t> decrypt(const Bytes32& key,
                                        const std::vector<uint8_t>& ciphertext);

    // Simple session-key derivation from the 512-bit master material
    static Bytes32 session_key_from_512(const Bytes64& master, uint64_t nonce);
};

} // namespace cyb3r
