#include "bce_ledger.hpp"
#include <openssl/sha.h>
#include <sstream>
#include <iomanip>

namespace cyb3r {

BCELedger::BCELedger() {
    ensure_genesis();
}

void BCELedger::ensure_genesis() {
    if (!chain_.empty()) return;
    LedgerEntry gen;
    gen.index = 0;
    gen.timestamp = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(
            Clock::now().time_since_epoch()).count());
    gen.event_type = "GENESIS";
    gen.dna_a = "00000000";
    gen.dna_b = "";
    gen.payload_hash = "";
    gen.prev_hash = "0";
    gen.entry_hash = compute_hash(gen);
    chain_.push_back(gen);
}

void BCELedger::reset() {
    chain_.clear();
    ensure_genesis();
}

std::string BCELedger::sha256_hex(const std::string& data) const {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(data.data()), data.size(), hash);
    return to_hex(hash, SHA256_DIGEST_LENGTH);
}

std::string BCELedger::compute_hash(const LedgerEntry& e) const {
    std::ostringstream oss;
    oss << e.index << "|" << e.timestamp << "|" << e.event_type << "|"
        << e.dna_a << "|" << e.dna_b << "|" << e.payload_hash << "|" << e.prev_hash;
    return sha256_hex(oss.str());
}

uint64_t BCELedger::append(const std::string& event_type,
                           const DNAIdentity& dna_a,
                           const DNAIdentity* dna_b,
                           const std::string& payload) {
    LedgerEntry e;
    e.index = chain_.size();
    e.timestamp = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(
            Clock::now().time_since_epoch()).count());
    e.event_type = event_type;
    e.dna_a = dna_a.hex;
    e.dna_b = dna_b ? dna_b->hex : "";
    e.payload_hash = payload.empty() ? "" : sha256_hex(payload);
    e.prev_hash = chain_.back().entry_hash;
    e.entry_hash = compute_hash(e);
    chain_.push_back(e);
    return e.index;
}

bool BCELedger::verify_integrity() const {
    if (chain_.empty()) return false;
    for (size_t i = 1; i < chain_.size(); ++i) {
        if (chain_[i].prev_hash != chain_[i - 1].entry_hash) return false;
        if (chain_[i].entry_hash != compute_hash(chain_[i])) return false;
    }
    return true;
}

void BCELedger::print_recent(size_t n) const {
    size_t start = chain_.size() > n ? chain_.size() - n : 0;
    for (size_t i = start; i < chain_.size(); ++i) {
        const auto& e = chain_[i];
        std::cout << "  [" << e.index << "] " << e.event_type
                  << "  DNA-A=" << short_hex(e.dna_a, 6);
        if (!e.dna_b.empty())
            std::cout << "  DNA-B=" << short_hex(e.dna_b, 6);
        std::cout << "  hash=" << short_hex(e.entry_hash, 8) << "\n";
    }
}

// Simple text format (one entry per line):
// INDEX|TS|TYPE|DNA_A|DNA_B|PAYLOAD_HASH|PREV_HASH|ENTRY_HASH
bool BCELedger::save(const std::string& path) const {
    std::ofstream ofs(path);
    if (!ofs) return false;
    for (const auto& e : chain_) {
        ofs << e.index << "|"
            << e.timestamp << "|"
            << e.event_type << "|"
            << e.dna_a << "|"
            << e.dna_b << "|"
            << e.payload_hash << "|"
            << e.prev_hash << "|"
            << e.entry_hash << "\n";
    }
    return true;
}

bool BCELedger::load(const std::string& path) {
    std::ifstream ifs(path);
    if (!ifs) return false;

    chain_.clear();
    std::string line;
    while (std::getline(ifs, line)) {
        if (line.empty()) continue;
        std::istringstream iss(line);
        LedgerEntry e;
        char delim;
        iss >> e.index >> delim
            >> e.timestamp >> delim;
        std::getline(iss, e.event_type, '|');
        std::getline(iss, e.dna_a, '|');
        std::getline(iss, e.dna_b, '|');
        std::getline(iss, e.payload_hash, '|');
        std::getline(iss, e.prev_hash, '|');
        std::getline(iss, e.entry_hash);
        chain_.push_back(e);
    }
    if (chain_.empty()) ensure_genesis();
    return true;
}

} // namespace cyb3r
