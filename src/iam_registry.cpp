#include "iam_registry.hpp"
#include <sstream>
#include <iomanip>

namespace cyb3r {

std::string IAMRegistry::make_mac(const Bytes32& raw) {
    std::ostringstream o;
    o << std::hex << std::setfill('0');
    for (int i = 0; i < 6; ++i) {
        if (i) o << ":";
        o << std::setw(2) << static_cast<unsigned>(raw[i] ^ raw[i + 8]);
    }
    return o.str();
}

std::string IAMRegistry::make_serial(const Bytes32& raw) {
    std::ostringstream o;
    o << "CYB-" << std::hex << std::uppercase << std::setfill('0');
    for (int i = 16; i < 24; ++i)
        o << std::setw(2) << static_cast<unsigned>(raw[i]);
    return o.str();
}

bool IAMRegistry::register_device(const DNAIdentity& dna,
                                  const std::string& notes,
                                  const std::string& mac,
                                  const std::string& serial) {
    std::lock_guard<std::mutex> lock(mtx_);
    if (devices_.count(dna.hex)) return false;

    DeviceRecord rec;
    rec.dna = dna;
    rec.status = "registered";
    rec.registered_ts = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(
            Clock::now().time_since_epoch()).count());
    rec.last_seen_ts = rec.registered_ts;
    rec.notes = notes;
    rec.mac_address = mac.empty() ? make_mac(dna.raw) : mac;
    rec.serial_number = serial.empty() ? make_serial(dna.raw) : serial;
    rec.firmware = "1.2.0-sim";
    rec.validation = "pending";
    rec.last_tx_hash = "";
    devices_[dna.hex] = rec;
    return true;
}

std::optional<DeviceRecord> IAMRegistry::find(const std::string& dna_hex) const {
    std::lock_guard<std::mutex> lock(mtx_);
    auto it = devices_.find(dna_hex);
    if (it == devices_.end()) return std::nullopt;
    return it->second;
}

std::optional<DeviceRecord> IAMRegistry::find(const DNAIdentity& dna) const {
    return find(dna.hex);
}

bool IAMRegistry::mark_active(const DNAIdentity& dna) {
    std::lock_guard<std::mutex> lock(mtx_);
    auto it = devices_.find(dna.hex);
    if (it == devices_.end()) return false;
    it->second.status = "active";
    it->second.validation = "validated";
    it->second.last_seen_ts = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(
            Clock::now().time_since_epoch()).count());
    return true;
}

bool IAMRegistry::revoke(const DNAIdentity& dna) {
    std::lock_guard<std::mutex> lock(mtx_);
    auto it = devices_.find(dna.hex);
    if (it == devices_.end()) return false;
    it->second.status = "revoked";
    it->second.validation = "revoked";
    return true;
}

bool IAMRegistry::set_validation(const DNAIdentity& dna, const std::string& validation) {
    std::lock_guard<std::mutex> lock(mtx_);
    auto it = devices_.find(dna.hex);
    if (it == devices_.end()) return false;
    it->second.validation = validation;
    return true;
}

bool IAMRegistry::set_last_tx(const DNAIdentity& dna, const std::string& tx_hash) {
    std::lock_guard<std::mutex> lock(mtx_);
    auto it = devices_.find(dna.hex);
    if (it == devices_.end()) return false;
    it->second.last_tx_hash = tx_hash;
    return true;
}

std::vector<DeviceRecord> IAMRegistry::list_all() const {
    std::lock_guard<std::mutex> lock(mtx_);
    std::vector<DeviceRecord> out;
    out.reserve(devices_.size());
    for (const auto& kv : devices_) out.push_back(kv.second);
    return out;
}

size_t IAMRegistry::count() const {
    std::lock_guard<std::mutex> lock(mtx_);
    return devices_.size();
}

size_t IAMRegistry::count_by_status(const std::string& status) const {
    std::lock_guard<std::mutex> lock(mtx_);
    size_t n = 0;
    for (const auto& kv : devices_)
        if (kv.second.status == status) ++n;
    return n;
}

bool IAMRegistry::authorize_pair(const DNAIdentity& a, const DNAIdentity& b) const {
    auto ra = find(a);
    auto rb = find(b);
    if (!ra || !rb) return false;
    return ra->status == "active" && rb->status == "active"
        && ra->validation == "validated" && rb->validation == "validated";
}

void IAMRegistry::clear() {
    std::lock_guard<std::mutex> lock(mtx_);
    devices_.clear();
}

// Extended text format:
// HEX|STATUS|REG_TS|LAST_TS|NOTES|MAC|SERIAL|FIRMWARE|VALIDATION|LAST_TX
bool IAMRegistry::save(const std::string& path) const {
    std::lock_guard<std::mutex> lock(mtx_);
    std::ofstream ofs(path);
    if (!ofs) return false;
    for (const auto& kv : devices_) {
        const auto& r = kv.second;
        ofs << r.dna.hex << "|"
            << r.status << "|"
            << r.registered_ts << "|"
            << r.last_seen_ts << "|"
            << r.notes << "|"
            << r.mac_address << "|"
            << r.serial_number << "|"
            << r.firmware << "|"
            << r.validation << "|"
            << r.last_tx_hash << "\n";
    }
    return true;
}

bool IAMRegistry::load(const std::string& path) {
    std::ifstream ifs(path);
    if (!ifs) return false;

    std::lock_guard<std::mutex> lock(mtx_);
    devices_.clear();
    std::string line;
    while (std::getline(ifs, line)) {
        if (line.empty()) continue;
        std::vector<std::string> parts;
        std::string part;
        std::istringstream iss(line);
        while (std::getline(iss, part, '|')) parts.push_back(part);
        if (parts.size() < 5 || parts[0].size() != 64) continue;

        Bytes32 raw{};
        for (size_t i = 0; i < 32; ++i) {
            unsigned int byte = 0;
            std::sscanf(parts[0].c_str() + i * 2, "%2x", &byte);
            raw[i] = static_cast<uint8_t>(byte);
        }
        DeviceRecord rec;
        rec.dna = DNAFactory::from_raw(raw, "loaded");
        rec.dna.hex = parts[0];
        rec.dna.short_id = short_hex(parts[0], 8);
        rec.status = parts[1];
        rec.registered_ts = std::stoull(parts[2]);
        rec.last_seen_ts = std::stoull(parts[3]);
        rec.notes = parts[4];
        rec.mac_address = parts.size() > 5 ? parts[5] : make_mac(raw);
        rec.serial_number = parts.size() > 6 ? parts[6] : make_serial(raw);
        rec.firmware = parts.size() > 7 ? parts[7] : "1.2.0-sim";
        rec.validation = parts.size() > 8 ? parts[8] : "pending";
        rec.last_tx_hash = parts.size() > 9 ? parts[9] : "";
        devices_[parts[0]] = rec;
    }
    return true;
}

} // namespace cyb3r
