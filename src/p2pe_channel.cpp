#include "p2pe_channel.hpp"

namespace cyb3r {

P2PEChannel::P2PEChannel(const DNAIdentity& local,
                         const DNAIdentity& remote,
                         const Bytes64& validation_key)
    : local_(local), remote_(remote)
{
    // Derive a direction-independent session key for the pair.
    // We always order the two DNA digests lexicographically so both
    // ends produce the identical 256-bit session key.
    const Bytes32& d1 = (local.hex < remote.hex) ? local.raw : remote.raw;
    const Bytes32& d2 = (local.hex < remote.hex) ? remote.raw : local.raw;

    uint64_t nonce = 0;
    for (size_t i = 0; i < 8; ++i) {
        nonce ^= (static_cast<uint64_t>(d1[i])     << (i * 8));
        nonce ^= (static_cast<uint64_t>(d2[i + 8]) << (i * 8));
    }
    session_key_ = AES_SEA::session_key_from_512(validation_key, nonce);
    open_ = true;

    LOG_OK("P2PE channel open: " + local.short_id + " → " + remote.short_id +
           "  session_key=" + short_hex(to_hex(session_key_)));
}

std::vector<uint8_t> P2PEChannel::send(const std::vector<uint8_t>& plaintext) {
    if (!open_) throw std::runtime_error("Channel is closed");
    auto ct = AES_SEA::encrypt(session_key_, plaintext);
    ++sent_;
    return ct;
}

std::vector<uint8_t> P2PEChannel::receive(const std::vector<uint8_t>& ciphertext) {
    if (!open_) throw std::runtime_error("Channel is closed");
    auto pt = AES_SEA::decrypt(session_key_, ciphertext);
    ++recv_;
    return pt;
}

} // namespace cyb3r
