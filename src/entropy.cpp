#include "entropy.hpp"
#include <cstring>
#include <thread>

namespace cyb3r {

EntropySource::EntropySource(uint64_t device_seed)
    : seed_(device_seed ? device_seed : 0xC3B3A11E0001ULL)
{
    // Mix high-resolution clock into the seed for uniqueness across runs
    auto now = high_res_timestamp();
    seed_ ^= now;
    seed_ ^= (now << 17) | (now >> 47);
    rng_.seed(seed_);
}

uint64_t EntropySource::high_res_timestamp() const {
    auto now = Clock::now().time_since_epoch();
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(now).count());
}

void EntropySource::mix_into(Bytes32& out, uint64_t value, size_t offset) const {
    for (size_t i = 0; i < 8 && (offset + i) < 32; ++i) {
        out[offset + i] ^= static_cast<uint8_t>((value >> (i * 8)) & 0xFF);
    }
}

Bytes32 EntropySource::collect_256() {
    Bytes32 block{};
    // Multiple entropy sources mixed together (simulates patent time + clock jitter)
    uint64_t t1 = high_res_timestamp();
    std::this_thread::sleep_for(std::chrono::microseconds(1 + (rng_() % 7)));
    uint64_t t2 = high_res_timestamp();
    uint64_t jitter = t2 - t1;

    uint64_t r1 = rng_();
    uint64_t r2 = rng_();
    uint64_t r3 = rng_();

    // Mix everything into the 32-byte block
    mix_into(block, t1, 0);
    mix_into(block, jitter, 4);
    mix_into(block, r1, 8);
    mix_into(block, r2, 16);
    mix_into(block, r3, 24);
    mix_into(block, seed_, 12);

    // Simple avalanche – XOR fold
    for (size_t i = 0; i < 16; ++i)
        block[i] ^= block[31 - i];

    // Very lightweight health heuristic
    uint64_t sum = 0;
    for (auto b : block) sum += b;
    if (sum == 0 || sum == 32 * 255) health_ok_ = false;

    last_ts_ = t2;
    return block;
}

std::vector<uint8_t> EntropySource::collect_raw(size_t num_bytes) {
    std::vector<uint8_t> out(num_bytes);
    size_t filled = 0;
    while (filled < num_bytes) {
        auto block = collect_256();
        size_t to_copy = std::min(size_t(32), num_bytes - filled);
        std::memcpy(out.data() + filled, block.data(), to_copy);
        filled += to_copy;
    }
    return out;
}

} // namespace cyb3r
