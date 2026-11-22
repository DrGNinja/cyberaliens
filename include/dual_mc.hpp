#pragma once
#include "common.hpp"
#include "entropy.hpp"
#include "dna_identity.hpp"
#include "aes_sea.hpp"

namespace cyb3r {

// Simulated 64-bit microcontroller (pure software model of the patent MC-A / MC-B)
class MicroController {
public:
    enum class Role { Master, Slave };

    MicroController(Role role, uint64_t seed, const std::string& name);

    // Boot / power-on sequence: collect entropy and form local DNA fragment
    void boot();

    // Exchange the 256-bit half with the peer over simulated I2C
    void exchange_key_material(MicroController& peer);

    // After exchange, both sides can compute the same 512-bit validation key
    Bytes64 compute_validation_key() const;

    // Accessors
    const DNAIdentity& dna() const { return dna_; }
    const Bytes32& local_half() const { return local_half_; }
    const Bytes32& peer_half() const { return peer_half_; }
    bool is_ready() const { return ready_; }
    Role role() const { return role_; }
    const std::string& name() const { return name_; }

private:
    Role role_;
    std::string name_;
    EntropySource entropy_;
    DNAIdentity dna_;
    Bytes32 local_half_{};
    Bytes32 peer_half_{};
    bool ready_ = false;
    bool exchanged_ = false;
};

// Convenience: create a matched pair (Master + Slave) that have already
// performed the key-exchange handshake.
struct DualMCPair {
    MicroController master;
    MicroController slave;
    Bytes64 validation_key;

    DualMCPair(uint64_t seed_a, uint64_t seed_b);
    void perform_handshake();
};

} // namespace cyb3r
