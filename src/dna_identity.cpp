#include "dna_identity.hpp"
#include <ctime>

namespace cyb3r {

DNAIdentity DNAFactory::create(EntropySource& src, const std::string& label) {
    DNAIdentity id;
    id.raw = src.collect_256();
    id.hex = to_hex(id.raw);
    id.short_id = short_hex(id.hex, 8);
    id.created_ts = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(
            Clock::now().time_since_epoch()).count());
    id.device_label = label.empty() ? ("DNA-" + id.short_id) : label;
    return id;
}

DNAIdentity DNAFactory::from_raw(const Bytes32& raw, const std::string& label) {
    DNAIdentity id;
    id.raw = raw;
    id.hex = to_hex(raw);
    id.short_id = short_hex(id.hex, 8);
    id.created_ts = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(
            Clock::now().time_since_epoch()).count());
    id.device_label = label.empty() ? ("DNA-" + id.short_id) : label;
    return id;
}

} // namespace cyb3r
