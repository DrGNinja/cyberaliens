#pragma once
#include "common.hpp"

namespace cyb3r {

// Simulates hardware entropy sources described in the patent:
// time-based jitter + clock-frequency noise + (optional) device-specific seed.
class EntropySource {
public:
    explicit EntropySource(uint64_t device_seed = 0);

    // Collect a fresh 256-bit entropy block (simulates the dual-MC collection)
    Bytes32 collect_256();

    // Collect raw entropy bits for health / statistics
    std::vector<uint8_t> collect_raw(size_t num_bytes);

    // Simple continuous health check (very lightweight simulation of SP 800-90B style)
    bool health_ok() const { return health_ok_; }

private:
    uint64_t seed_;
    mutable std::mt19937_64 rng_;
    mutable std::atomic<bool> health_ok_{true};
    mutable uint64_t last_ts_{0};

    uint64_t high_res_timestamp() const;
    void mix_into(Bytes32& out, uint64_t value, size_t offset) const;
};

} // namespace cyb3r
