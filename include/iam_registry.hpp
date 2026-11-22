#pragma once
#include "common.hpp"
#include "dna_identity.hpp"
#include <unordered_map>
#include <vector>
#include <optional>
#include <fstream>

namespace cyb3r {

// Patent-aligned device record (IAM central database view)
// Fields mirror US10673617B1 concepts: DNA/fingerprint, MAC, serial, status, validation
struct DeviceRecord {
    DNAIdentity dna;
    std::string status;          // "registered", "active", "revoked", "pending"
    uint64_t registered_ts;
    uint64_t last_seen_ts;
    std::string notes;

    // Patent-style identity attributes
    std::string mac_address;     // simulated unique MAC
    std::string serial_number;   // simulated unique serial
    std::string firmware;        // e.g. "1.0.0-sim"
    std::string validation;      // "validated" | "unvalidated" | "revoked"
    std::string last_tx_hash;    // last BCE transaction hash involving this device
};

class IAMRegistry {
public:
    bool register_device(const DNAIdentity& dna,
                        const std::string& notes = "",
                        const std::string& mac = "",
                        const std::string& serial = "");

    std::optional<DeviceRecord> find(const std::string& dna_hex) const;
    std::optional<DeviceRecord> find(const DNAIdentity& dna) const;

    bool mark_active(const DNAIdentity& dna);
    bool revoke(const DNAIdentity& dna);
    bool set_validation(const DNAIdentity& dna, const std::string& validation);
    bool set_last_tx(const DNAIdentity& dna, const std::string& tx_hash);

    std::vector<DeviceRecord> list_all() const;
    size_t count() const;
    size_t count_by_status(const std::string& status) const;

    bool authorize_pair(const DNAIdentity& a, const DNAIdentity& b) const;

    bool save(const std::string& path) const;
    bool load(const std::string& path);
    void clear();

private:
    std::unordered_map<std::string, DeviceRecord> devices_;
    mutable std::mutex mtx_;

    static std::string make_mac(const Bytes32& raw);
    static std::string make_serial(const Bytes32& raw);
};

} // namespace cyb3r
