#pragma once
#include "common.hpp"
#include "dna_identity.hpp"
#include <vector>
#include <string>
#include <fstream>

namespace cyb3r {

// Blockchain Ecosystem (BCE) – lightweight append-only ledger for device events
struct LedgerEntry {
    uint64_t index;
    uint64_t timestamp;
    std::string event_type;      // "REGISTER", "AUTH", "CHANNEL_OPEN", "MSG", "REVOKE"
    std::string dna_a;           // primary DNA hex
    std::string dna_b;           // optional second DNA
    std::string payload_hash;    // hash of associated data
    std::string prev_hash;       // previous block hash (simple chain)
    std::string entry_hash;      // this entry's hash
};

class BCELedger {
public:
    BCELedger();

    // Append an event; returns the new entry index
    uint64_t append(const std::string& event_type,
                    const DNAIdentity& dna_a,
                    const DNAIdentity* dna_b = nullptr,
                    const std::string& payload = "");

    // Query
    const std::vector<LedgerEntry>& entries() const { return chain_; }
    size_t size() const { return chain_.size(); }
    bool verify_integrity() const;

    // Pretty print last N entries
    void print_recent(size_t n = 10) const;

    // Persistence
    bool save(const std::string& path) const;
    bool load(const std::string& path);

    // Reset to genesis only
    void reset();

private:
    std::vector<LedgerEntry> chain_;
    std::string compute_hash(const LedgerEntry& e) const;
    std::string sha256_hex(const std::string& data) const;
    void ensure_genesis();
};

} // namespace cyb3r
