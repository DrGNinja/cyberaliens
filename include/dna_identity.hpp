#pragma once
#include "common.hpp"
#include "entropy.hpp"

namespace cyb3r {

// Digital DNA – immutable device identity derived from entropy
// Matches the patent concept of a unique, non-clonable identity token.
struct DNAIdentity {
    Bytes32 raw;                 // 256-bit core identity
    std::string hex;             // canonical hex representation
    std::string short_id;        // human-friendly short form
    uint64_t created_ts;         // creation timestamp (simulated)
    std::string device_label;    // optional label (e.g. "Device-A")

    bool operator==(const DNAIdentity& o) const { return raw == o.raw; }
    bool operator!=(const DNAIdentity& o) const { return !(*this == o); }
};

class DNAFactory {
public:
    // Create a new DNA from a live entropy source
    static DNAIdentity create(EntropySource& src, const std::string& label = "");

    // Reconstruct / load from known raw bytes (for simulation persistence)
    static DNAIdentity from_raw(const Bytes32& raw, const std::string& label = "");
};

} // namespace cyb3r
