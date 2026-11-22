#pragma once
#include "common.hpp"
#include <vector>
#include <string>
#include <mutex>
#include <chrono>

namespace cyb3r {

// Structured event that mirrors patent process stages so investors can follow
// the exact sequence described in US10673617B1 (esp. Fig. 15 and claims).
struct ProcessEvent {
    uint64_t    seq;            // monotonic sequence number
    uint64_t    ts_ms;          // milliseconds since epoch
    std::string stage;          // e.g. "I2C", "CIPHER1", "CIPHER2", "ENTROPY", "DNA", "IAM", "BCE", "P2PE"
    std::string step;           // short human label
    std::string detail;         // longer explanation / values
    std::string status;         // "ok" | "warn" | "error"
};

class ProcessTrace {
public:
    void clear();
    void record(const std::string& stage,
                const std::string& step,
                const std::string& detail = "",
                const std::string& status = "ok");

    std::vector<ProcessEvent> snapshot() const;
    size_t size() const;
    std::string to_json() const;   // for API / dashboard

private:
    mutable std::mutex mtx_;
    std::vector<ProcessEvent> events_;
    uint64_t next_seq_ = 1;
};

// Global process trace used by the simulation engine and web API
ProcessTrace& global_trace();

} // namespace cyb3r
