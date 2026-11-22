#pragma once

#include <array>
#include <cstdint>
#include <string>
#include <vector>
#include <chrono>
#include <sstream>
#include <iomanip>
#include <random>
#include <stdexcept>
#include <iostream>
#include <mutex>
#include <atomic>

namespace cyb3r {

using Clock = std::chrono::high_resolution_clock;
using TimePoint = Clock::time_point;

// Fixed-size byte containers matching patent-style 256/512-bit material
using Bytes32 = std::array<uint8_t, 32>;   // 256-bit
using Bytes64 = std::array<uint8_t, 64>;   // 512-bit

inline std::string to_hex(const uint8_t* data, size_t len) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (size_t i = 0; i < len; ++i)
        oss << std::setw(2) << static_cast<unsigned>(data[i]);
    return oss.str();
}

template <size_t N>
inline std::string to_hex(const std::array<uint8_t, N>& a) {
    return to_hex(a.data(), N);
}

inline std::string short_hex(const std::string& full, size_t keep = 12) {
    if (full.size() <= keep * 2) return full;
    return full.substr(0, keep) + "…" + full.substr(full.size() - keep);
}

// Simple thread-safe logger for the demo
class Logger {
public:
    static Logger& instance() {
        static Logger L;
        return L;
    }
    void info(const std::string& msg) {
        std::lock_guard<std::mutex> lock(m_);
        std::cout << "[INFO]  " << msg << "\n";
    }
    void ok(const std::string& msg) {
        std::lock_guard<std::mutex> lock(m_);
        std::cout << "[ OK ]  " << msg << "\n";
    }
    void warn(const std::string& msg) {
        std::lock_guard<std::mutex> lock(m_);
        std::cout << "[WARN]  " << msg << "\n";
    }
    void step(const std::string& msg) {
        std::lock_guard<std::mutex> lock(m_);
        std::cout << "\n=== " << msg << " ===\n";
    }
private:
    std::mutex m_;
};

#define LOG_INFO(m)  cyb3r::Logger::instance().info(m)
#define LOG_OK(m)    cyb3r::Logger::instance().ok(m)
#define LOG_WARN(m)  cyb3r::Logger::instance().warn(m)
#define LOG_STEP(m)  cyb3r::Logger::instance().step(m)

} // namespace cyb3r
