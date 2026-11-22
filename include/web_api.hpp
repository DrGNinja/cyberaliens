#pragma once
#include "iam_registry.hpp"
#include "bce_ledger.hpp"
#include "dual_mc.hpp"
#include "p2pe_channel.hpp"
#include <string>
#include <mutex>
#include <memory>
#include <vector>

namespace cyb3r {

// In-memory simulation state shared by the HTTP API
struct DevicePair {
    std::unique_ptr<DualMCPair> pair;
    Bytes64 validation_key{};
    DNAIdentity dna_a;
    DNAIdentity dna_b;
    uint64_t created_ts = 0;
    std::string label;
};

struct SimState {
    IAMRegistry iam;
    BCELedger   ledger;
    std::mutex  mtx;

    // Fleet of dual-MC pairs (supports multiple concurrent devices)
    std::vector<DevicePair> fleet;
    size_t active_pair_idx = 0;   // index into fleet for P2PE
    bool has_pair = false;

    // Failure injection flags (for security storytelling demos)
    bool inject_entropy_fail = false;
    bool inject_key_mismatch = false;
    bool inject_revoke_block = false;
};

// Start the embedded HTTP server (blocks). Serves both API and static files.
void run_web_server(SimState& state, const std::string& static_dir, int port = 8080);

} // namespace cyb3r
