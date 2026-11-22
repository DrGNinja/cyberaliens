#include "dual_mc.hpp"
#include "aes_sea.hpp"
#include "process_trace.hpp"

namespace cyb3r {

MicroController::MicroController(Role role, uint64_t seed, const std::string& name)
    : role_(role), name_(name), entropy_(seed)
{}

void MicroController::boot() {
    global_trace().record("BOOT", name_ + " power-on",
        "Role=" + std::string(role_ == Role::Master ? "Master" : "Slave") +
        " | Entropy source seeded");

    // Patent: collect entropy (time + clock frequency jitter)
    global_trace().record("ENTROPY", name_ + " collecting entropy",
        "Sources: high-res timestamps + clock jitter (patent time/clock-frequency PRNG)");

    local_half_ = entropy_.collect_256();
    auto health = entropy_.health_ok() ? "OK" : "DEGRADED";
    global_trace().record("ENTROPY", name_ + " entropy block ready",
        "256-bit material=" + short_hex(to_hex(local_half_)) + " | health=" + health,
        entropy_.health_ok() ? "ok" : "warn");

    // Patent: generate Digital DNA / fingerprint identity
    dna_ = DNAFactory::create(entropy_, name_);
    global_trace().record("DNA", name_ + " Digital DNA created",
        "Fingerprint=" + dna_.short_id + " (immutable device identity)");

    // Patent: Cipher 1 – AES-SEA 256-bit key on this MC
    global_trace().record("CIPHER1", name_ + " Cipher 1 (AES-SEA 256-bit)",
        "Local half-key generated | channel=" +
        std::string(role_ == Role::Master ? "1A" : "1B"));

    ready_ = true;
}

void MicroController::exchange_key_material(MicroController& peer) {
    if (!ready_ || !peer.ready_)
        throw std::runtime_error("Both MCs must be booted before exchange");

    // Patent: I2C bus transaction (Master ↔ Slave)
    global_trace().record("I2C", "I2C bus start",
        "Master/Slave TWI | SDA/SCL simulated | 10-bit addressing model");

    global_trace().record("I2C", name_ + " → " + peer.name_ + " write local half",
        "Transferring 256-bit Cipher-1 material over simulated I2C");

    // Simulated I2C transfer
    peer_half_      = peer.local_half_;
    peer.peer_half_ = local_half_;
    exchanged_ = true;
    peer.exchanged_ = true;

    global_trace().record("I2C", "I2C exchange complete + ACK",
        name_ + " now holds peer half | " + peer.name_ + " now holds peer half");

    // Patent: Cipher 2 begins – both sides now have both halves
    global_trace().record("CIPHER2", "Cipher 2 preparation",
        "Both MCs hold Cipher-1 halves | ready for 512-bit AES-SEA derivation");
}

Bytes64 MicroController::compute_validation_key() const {
    if (!exchanged_)
        throw std::runtime_error("Cannot compute validation key before exchange");

    // Deterministic order: Master half first
    if (role_ == Role::Master)
        return AES_SEA::derive_512(local_half_, peer_half_);
    else
        return AES_SEA::derive_512(peer_half_, local_half_);
}

// ---------- DualMCPair ----------

DualMCPair::DualMCPair(uint64_t seed_a, uint64_t seed_b)
    : master(MicroController::Role::Master, seed_a, "MC-A (Master)"),
      slave (MicroController::Role::Slave,  seed_b, "MC-B (Slave)"),
      validation_key{}
{}

void DualMCPair::perform_handshake() {
    global_trace().record("SYSTEM", "Dual-MC handshake begin",
        "Patent flow: Boot → Entropy → Cipher 1 → I2C → Cipher 2 → 512-bit key");

    master.boot();
    slave.boot();

    master.exchange_key_material(slave);

    // Both sides independently compute the same 512-bit validation key
    auto key_m = master.compute_validation_key();
    auto key_s = slave.compute_validation_key();

    if (key_m != key_s) {
        global_trace().record("CIPHER2", "Validation key MISMATCH",
            "Master and Slave derived different 512-bit keys", "error");
        throw std::runtime_error("Validation key mismatch between Master and Slave!");
    }

    validation_key = key_m;

    global_trace().record("CIPHER2", "AES-SEA 512-bit validation key established",
        "Key=" + short_hex(to_hex(validation_key)) +
        " | 10 mixing rounds completed | identical on MC-A and MC-B");

    global_trace().record("SYSTEM", "Dual-MC handshake SUCCESS",
        "P2PE material ready | devices can now register with IAM / BCE");
}

} // namespace cyb3r
