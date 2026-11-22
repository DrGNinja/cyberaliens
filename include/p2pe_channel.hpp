#pragma once
#include "common.hpp"
#include "aes_sea.hpp"
#include "dna_identity.hpp"

namespace cyb3r {

// Point-to-Point Encryption channel (pure software simulation of the patent P2PE)
class P2PEChannel {
public:
    // Establish a secure channel between two DNA identities using the shared
    // 512-bit validation key (derived from the dual-MC handshake).
    P2PEChannel(const DNAIdentity& local,
                const DNAIdentity& remote,
                const Bytes64& validation_key);

    // Encrypt a message for the remote party
    std::vector<uint8_t> send(const std::vector<uint8_t>& plaintext);

    // Decrypt a message received from the remote party
    std::vector<uint8_t> receive(const std::vector<uint8_t>& ciphertext);

    // Simple integrity / status
    bool is_open() const { return open_; }
    const DNAIdentity& local() const { return local_; }
    const DNAIdentity& remote() const { return remote_; }
    uint64_t messages_sent() const { return sent_; }
    uint64_t messages_received() const { return recv_; }

private:
    DNAIdentity local_;
    DNAIdentity remote_;
    Bytes32 session_key_;
    bool open_ = false;
    uint64_t sent_ = 0;
    uint64_t recv_ = 0;
    uint64_t nonce_counter_ = 1;
};

} // namespace cyb3r
