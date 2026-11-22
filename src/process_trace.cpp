#include "process_trace.hpp"
#include <sstream>

namespace cyb3r {

void ProcessTrace::clear() {
    std::lock_guard<std::mutex> lock(mtx_);
    events_.clear();
    next_seq_ = 1;
}

void ProcessTrace::record(const std::string& stage,
                          const std::string& step,
                          const std::string& detail,
                          const std::string& status) {
    std::lock_guard<std::mutex> lock(mtx_);
    ProcessEvent e;
    e.seq = next_seq_++;
    e.ts_ms = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            Clock::now().time_since_epoch()).count());
    e.stage = stage;
    e.step = step;
    e.detail = detail;
    e.status = status;
    events_.push_back(e);
}

std::vector<ProcessEvent> ProcessTrace::snapshot() const {
    std::lock_guard<std::mutex> lock(mtx_);
    return events_;
}

size_t ProcessTrace::size() const {
    std::lock_guard<std::mutex> lock(mtx_);
    return events_.size();
}

std::string ProcessTrace::to_json() const {
    std::lock_guard<std::mutex> lock(mtx_);
    std::ostringstream o;
    o << "{\"events\":[";
    for (size_t i = 0; i < events_.size(); ++i) {
        const auto& e = events_[i];
        if (i) o << ",";
        // Minimal JSON escaping
        auto esc = [](const std::string& s) {
            std::string r;
            for (char c : s) {
                if (c == '"') r += "\\\"";
                else if (c == '\\') r += "\\\\";
                else if (c == '\n') r += "\\n";
                else r += c;
            }
            return r;
        };
        o << "{"
          << "\"seq\":" << e.seq << ","
          << "\"ts_ms\":" << e.ts_ms << ","
          << "\"stage\":\"" << esc(e.stage) << "\","
          << "\"step\":\"" << esc(e.step) << "\","
          << "\"detail\":\"" << esc(e.detail) << "\","
          << "\"status\":\"" << esc(e.status) << "\""
          << "}";
    }
    o << "],\"count\":" << events_.size() << "}";
    return o.str();
}

ProcessTrace& global_trace() {
    static ProcessTrace t;
    return t;
}

} // namespace cyb3r
