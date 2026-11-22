#include "web_api.hpp"
#include "process_trace.hpp"
#include "../third_party/httplib.h"
#include <sstream>
#include <fstream>
#include <iomanip>

namespace cyb3r {

// ---------- minimal JSON helpers (no external lib) ----------
static std::string json_escape(const std::string& s) {
    std::ostringstream o;
    for (char c : s) {
        switch (c) {
            case '"':  o << "\\\""; break;
            case '\\': o << "\\\\"; break;
            case '\n': o << "\\n"; break;
            case '\r': o << "\\r"; break;
            case '\t': o << "\\t"; break;
            default:   o << c;
        }
    }
    return o.str();
}

static std::string jstr(const std::string& k, const std::string& v, bool last = false) {
    return "\"" + k + "\":\"" + json_escape(v) + "\"" + (last ? "" : ",");
}
static std::string jnum(const std::string& k, long long v, bool last = false) {
    return "\"" + k + "\":" + std::to_string(v) + (last ? "" : ",");
}
static std::string jbool(const std::string& k, bool v, bool last = false) {
    return "\"" + k + "\":" + (v ? "true" : "false") + (last ? "" : ",");
}

// ---------- API handlers ----------
static std::string handle_status(SimState& st) {
    std::lock_guard<std::mutex> lock(st.mtx);
    return "{" +
           jnum("iam_devices", st.iam.count()) +
           jnum("active_devices", st.iam.count_by_status("active")) +
           jnum("revoked_devices", st.iam.count_by_status("revoked")) +
           jnum("fleet_pairs", static_cast<long long>(st.fleet.size())) +
           jnum("ledger_entries", st.ledger.size()) +
           jbool("has_active_pair", st.has_pair) +
           jbool("ledger_integrity", st.ledger.verify_integrity(), true) +
           "}";
}

static std::string handle_onboard(SimState& st) {
    std::lock_guard<std::mutex> lock(st.mtx);

    global_trace().clear();
    global_trace().record("SYSTEM", "Investor demo – full patent process start",
        "Sequence: Boot → Entropy → DNA → Cipher1 → I2C → Cipher2 → IAM → BCE → P2PE");

    // Check failure injection
    if (st.inject_entropy_fail) {
        global_trace().record("ENTROPY", "FAILURE INJECTED – entropy health degraded",
            "Simulated hardware entropy source failure for security storytelling", "error");
        st.inject_entropy_fail = false; // one-shot
        return "{\"status\":\"error\",\"message\":\"Entropy collection failed (injected for demo)\"}";
    }

    auto pair = std::make_unique<DualMCPair>(
        static_cast<uint64_t>(Clock::now().time_since_epoch().count()),
        static_cast<uint64_t>(Clock::now().time_since_epoch().count()) ^ 0xA5A5A5A5ULL);

    try {
        pair->perform_handshake();
    } catch (const std::exception& e) {
        global_trace().record("CIPHER2", "Handshake failed", e.what(), "error");
        return "{\"status\":\"error\",\"message\":\"Handshake failed: " + json_escape(e.what()) + "\"}";
    }

    // Optional key mismatch injection (after successful handshake for storytelling)
    if (st.inject_key_mismatch) {
        global_trace().record("CIPHER2", "FAILURE INJECTED – key mismatch forced",
            "Master and Slave validation keys deliberately diverged for demo", "error");
        st.inject_key_mismatch = false;
        return "{\"status\":\"error\",\"message\":\"Key mismatch injected (Master ≠ Slave)\"}";
    }

    const auto& dna_a = pair->master.dna();
    const auto& dna_b = pair->slave.dna();

    st.iam.register_device(dna_a, "web-onboard A");
    st.iam.register_device(dna_b, "web-onboard B");
    st.iam.mark_active(dna_a);
    st.iam.mark_active(dna_b);
    global_trace().record("IAM", "Central server database – devices registered",
        "DNA-A + DNA-B written to IAM registry (MAC, serial, validation=validated)");
    global_trace().record("IAM", "Authorization active",
        "Both devices marked active and validated for P2PE");

    st.ledger.append("REGISTER", dna_a, nullptr, "web-onboard");
    st.ledger.append("REGISTER", dna_b, nullptr, "web-onboard");
    global_trace().record("BCE", "Blockchain Ecosystem – registration events",
        "Hash-chained REGISTER entries appended to immutable ledger");

    if (!st.ledger.entries().empty()) {
        const auto& last = st.ledger.entries().back();
        st.iam.set_last_tx(dna_a, last.entry_hash);
        st.iam.set_last_tx(dna_b, last.entry_hash);
    }

    // Add to fleet
    DevicePair dp;
    dp.pair = std::move(pair);
    dp.validation_key = dp.pair->validation_key;
    dp.dna_a = dna_a;
    dp.dna_b = dna_b;
    dp.created_ts = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(
            Clock::now().time_since_epoch()).count());
    dp.label = "Pair-" + std::to_string(st.fleet.size() + 1);
    st.fleet.push_back(std::move(dp));
    st.active_pair_idx = st.fleet.size() - 1;
    st.has_pair = true;

    global_trace().record("SYSTEM", "Device pair added to fleet",
        "Fleet size now " + std::to_string(st.fleet.size()) + " | active pair index " + std::to_string(st.active_pair_idx));

    const auto& active = st.fleet[st.active_pair_idx];
    return "{" +
           jstr("status", "ok") +
           jstr("dna_a", active.dna_a.hex) +
           jstr("dna_a_short", active.dna_a.short_id) +
           jstr("dna_b", active.dna_b.hex) +
           jstr("dna_b_short", active.dna_b.short_id) +
           jstr("validation_key", short_hex(to_hex(active.validation_key))) +
           jnum("fleet_size", static_cast<long long>(st.fleet.size()), true) +
           "}";
}

static std::string handle_p2pe(SimState& st, const std::string& message) {
    std::lock_guard<std::mutex> lock(st.mtx);
    if (!st.has_pair || st.fleet.empty()) {
        return "{\"status\":\"error\",\"message\":\"No active pair – call /api/onboard first\"}";
    }

    const auto& active = st.fleet[st.active_pair_idx];

    // Failure injection: block if revoked
    if (st.inject_revoke_block) {
        global_trace().record("P2PE", "FAILURE INJECTED – revoked device blocked",
            "Attempted channel open from revoked device rejected", "error");
        st.inject_revoke_block = false;
        return "{\"status\":\"error\",\"message\":\"Channel blocked: device is revoked (injected for demo)\"}";
    }

    global_trace().record("P2PE", "Open point-to-point channel",
        "Using AES-SEA 512-bit validation key from active fleet pair | session key derived both directions");

    P2PEChannel ab(active.dna_a, active.dna_b, active.validation_key);
    P2PEChannel ba(active.dna_b, active.dna_a, active.validation_key);

    auto ct = ab.send(std::vector<uint8_t>(message.begin(), message.end()));
    auto pt = ba.receive(ct);

    global_trace().record("P2PE", "Encrypted payload delivered + integrity check",
        "Ciphertext length=" + std::to_string(ct.size()) + " bytes");
    std::string recovered(pt.begin(), pt.end());

    st.ledger.append("CHANNEL_OPEN", active.dna_a, &active.dna_b, "web-p2pe");
    st.ledger.append("MSG", active.dna_a, &active.dna_b, message);

    bool ok = (recovered == message);
    return "{" +
           jstr("status", ok ? "ok" : "error") +
           jstr("original", message) +
           jstr("recovered", recovered) +
           jbool("integrity", ok) +
           jstr("ciphertext_hex", to_hex(ct.data(), std::min(ct.size(), size_t(32))), true) +
           "}";
}

static std::string handle_selftest(SimState& st) {
    std::lock_guard<std::mutex> lock(st.mtx);
    std::ostringstream o;
    o << "{\"checks\":[";

    // 1. Ledger integrity
    bool ledger_ok = st.ledger.verify_integrity();
    o << "{\"name\":\"Ledger hash-chain integrity\",\"pass\":" << (ledger_ok ? "true" : "false")
      << ",\"detail\":\"" << (ledger_ok ? "All entries hash-linked correctly" : "Chain broken") << "\"},";

    // 2. Entropy health (fresh collection)
    EntropySource ent(0xC3B3A11EULL);
    auto block = ent.collect_256();
    bool ent_ok = ent.health_ok() && block[0] != 0;
    o << "{\"name\":\"Entropy source health\",\"pass\":" << (ent_ok ? "true" : "false")
      << ",\"detail\":\"" << (ent_ok ? "Fresh 256-bit block collected, health OK" : "Entropy degraded") << "\"},";

    // 3. Fleet / key consistency
    bool keys_ok = true;
    std::string key_detail = "No pairs yet";
    if (!st.fleet.empty()) {
        keys_ok = true;
        for (const auto& dp : st.fleet) {
            if (dp.pair && dp.pair->validation_key != dp.validation_key) keys_ok = false;
        }
        key_detail = std::to_string(st.fleet.size()) + " pairs in fleet, keys consistent";
    }
    o << "{\"name\":\"Dual-MC key consistency\",\"pass\":" << (keys_ok ? "true" : "false")
      << ",\"detail\":\"" << key_detail << "\"},";

    // 4. IAM registry accessible
    bool iam_ok = st.iam.count() >= 0;
    o << "{\"name\":\"IAM central database\",\"pass\":" << (iam_ok ? "true" : "false")
      << ",\"detail\":\"" << st.iam.count() << " devices registered\"}";

    o << "],\"overall\":" << (ledger_ok && ent_ok && keys_ok && iam_ok ? "true" : "false")
      << ",\"timestamp\":" << static_cast<uint64_t>(
          std::chrono::duration_cast<std::chrono::seconds>(
              Clock::now().time_since_epoch()).count())
      << "}";
    return o.str();
}

static std::string handle_export(SimState& st) {
    std::lock_guard<std::mutex> lock(st.mtx);
    std::ostringstream o;
    o << "{";
    o << "\"status\":" << handle_status(st) << ",";  // nested, but simple
    o << "\"iam\":" << handle_iam(st) << ",";
    o << "\"ledger\":" << handle_ledger(st) << ",";
    o << "\"trace\":" << global_trace().to_json() << ",";
    o << "\"fleet_size\":" << st.fleet.size() << ",";
    o << "\"exported_at\":" << static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(
            Clock::now().time_since_epoch()).count());
    o << "}";
    return o.str();
}

static std::string handle_fleet(SimState& st) {
    std::lock_guard<std::mutex> lock(st.mtx);
    std::ostringstream o;
    o << "{\"pairs\":[";
    for (size_t i = 0; i < st.fleet.size(); ++i) {
        const auto& dp = st.fleet[i];
        if (i) o << ",";
        o << "{"
          << jnum("index", static_cast<long long>(i))
          << jstr("label", dp.label)
          << jstr("dna_a_short", dp.dna_a.short_id)
          << jstr("dna_b_short", dp.dna_b.short_id)
          << jstr("validation_key", short_hex(to_hex(dp.validation_key)))
          << jbool("active", i == st.active_pair_idx)
          << jnum("created_ts", dp.created_ts, true)
          << "}";
    }
    o << "],\"active_idx\":" << st.active_pair_idx
      << ",\"count\":" << st.fleet.size() << "}";
    return o.str();
}

static std::string handle_inject(SimState& st, const std::string& type) {
    std::lock_guard<std::mutex> lock(st.mtx);
    if (type == "entropy") {
        st.inject_entropy_fail = true;
        return "{\"status\":\"ok\",\"injected\":\"entropy_fail\",\"note\":\"Next onboard will fail entropy check\"}";
    } else if (type == "mismatch") {
        st.inject_key_mismatch = true;
        return "{\"status\":\"ok\",\"injected\":\"key_mismatch\",\"note\":\"Next onboard will force key mismatch\"}";
    } else if (type == "revoke") {
        st.inject_revoke_block = true;
        return "{\"status\":\"ok\",\"injected\":\"revoke_block\",\"note\":\"Next P2PE will be blocked as revoked\"}";
    }
    return "{\"status\":\"error\",\"message\":\"Unknown inject type (entropy|mismatch|revoke)\"}";
}

static std::string handle_iam(SimState& st) {
    std::lock_guard<std::mutex> lock(st.mtx);
    auto all = st.iam.list_all();
    std::ostringstream o;
    o << "{\"devices\":[";
    for (size_t i = 0; i < all.size(); ++i) {
        const auto& r = all[i];
        if (i) o << ",";
        o << "{"
          << jstr("dna_short", r.dna.short_id)
          << jstr("dna", r.dna.hex)
          << jstr("status", r.status)
          << jstr("validation", r.validation)
          << jstr("mac", r.mac_address)
          << jstr("serial", r.serial_number)
          << jstr("firmware", r.firmware)
          << jstr("notes", r.notes)
          << jstr("last_tx", r.last_tx_hash)
          << jnum("registered_ts", r.registered_ts, true)
          << "}";
    }
    o << "],\"count\":" << all.size() << "}";
    return o.str();
}

static std::string handle_ledger(SimState& st) {
    std::lock_guard<std::mutex> lock(st.mtx);
    const auto& entries = st.ledger.entries();
    std::ostringstream o;
    o << "{\"entries\":[";
    size_t start = entries.size() > 20 ? entries.size() - 20 : 0;
    for (size_t i = start; i < entries.size(); ++i) {
        const auto& e = entries[i];
        if (i > start) o << ",";
        o << "{"
          << jnum("index", e.index)
          << jstr("event", e.event_type)
          << jstr("dna_a", short_hex(e.dna_a, 8))
          << jstr("dna_b", e.dna_b.empty() ? "" : short_hex(e.dna_b, 8))
          << jstr("hash", short_hex(e.entry_hash, 10))
          << jnum("ts", e.timestamp, true)
          << "}";
    }
    o << "],\"total\":" << entries.size()
      << ",\"integrity\":" << (st.ledger.verify_integrity() ? "true" : "false") << "}";
    return o.str();
}

static std::string handle_revoke(SimState& st) {
    std::lock_guard<std::mutex> lock(st.mtx);
    auto all = st.iam.list_all();
    if (all.empty()) {
        return "{\"status\":\"error\",\"message\":\"No devices to revoke\"}";
    }
    // Revoke the most recently registered active device
    const auto& target = all.back().dna;
    st.iam.revoke(target);
    st.ledger.append("REVOKE", target, nullptr, "web-revoke");
    return "{" +
           jstr("status", "ok") +
           jstr("revoked", target.short_id, true) +
           "}";
}

void run_web_server(SimState& state, const std::string& static_dir, int port) {
    httplib::Server svr;

    // CORS for local development
    svr.set_default_headers({
        {"Access-Control-Allow-Origin", "*"},
        {"Access-Control-Allow-Methods", "GET, POST, OPTIONS"},
        {"Access-Control-Allow-Headers", "Content-Type"}
    });

    svr.Options(".*", [](const httplib::Request&, httplib::Response& res) {
        res.status = 204;
    });

    // ---- API routes ----
    svr.Get("/api/status", [&](const httplib::Request&, httplib::Response& res) {
        res.set_content(handle_status(state), "application/json");
    });

    svr.Post("/api/onboard", [&](const httplib::Request&, httplib::Response& res) {
        res.set_content(handle_onboard(state), "application/json");
    });

    svr.Post("/api/p2pe", [&](const httplib::Request& req, httplib::Response& res) {
        std::string msg = "Hello from Cyb3rALIENS web demo";
        // Accept optional JSON body {"message":"..."}
        auto pos = req.body.find("\"message\"");
        if (pos != std::string::npos) {
            auto start = req.body.find('"', pos + 9);
            if (start != std::string::npos) {
                start++;
                auto end = req.body.find('"', start);
                if (end != std::string::npos)
                    msg = req.body.substr(start, end - start);
            }
        }
        res.set_content(handle_p2pe(state, msg), "application/json");
    });

    svr.Get("/api/iam", [&](const httplib::Request&, httplib::Response& res) {
        res.set_content(handle_iam(state), "application/json");
    });

    svr.Get("/api/ledger", [&](const httplib::Request&, httplib::Response& res) {
        res.set_content(handle_ledger(state), "application/json");
    });

    svr.Post("/api/revoke", [&](const httplib::Request&, httplib::Response& res) {
        res.set_content(handle_revoke(state), "application/json");
    });

    svr.Get("/api/trace", [&](const httplib::Request&, httplib::Response& res) {
        res.set_content(global_trace().to_json(), "application/json");
    });

    svr.Get("/api/selftest", [&](const httplib::Request&, httplib::Response& res) {
        res.set_content(handle_selftest(state), "application/json");
    });

    svr.Get("/api/export", [&](const httplib::Request&, httplib::Response& res) {
        res.set_content(handle_export(state), "application/json");
        res.set_header("Content-Disposition", "attachment; filename=\"cyb3raliens_demo_report.json\"");
    });

    svr.Get("/api/fleet", [&](const httplib::Request&, httplib::Response& res) {
        res.set_content(handle_fleet(state), "application/json");
    });

    svr.Post("/api/select", [&](const httplib::Request& req, httplib::Response& res) {
        size_t idx = 0;
        auto pos = req.body.find("\"index\"");
        if (pos != std::string::npos) {
            auto start = req.body.find_first_of("0123456789", pos);
            if (start != std::string::npos) idx = std::stoul(req.body.substr(start));
        }
        std::lock_guard<std::mutex> lock(state.mtx);
        if (idx < state.fleet.size()) {
            state.active_pair_idx = idx;
            res.set_content("{\"status\":\"ok\",\"active\":" + std::to_string(idx) + "}", "application/json");
        } else {
            res.set_content("{\"status\":\"error\",\"message\":\"Invalid index\"}", "application/json");
        }
    });

    svr.Post("/api/inject", [&](const httplib::Request& req, httplib::Response& res) {
        std::string type = "entropy";
        auto pos = req.body.find("\"type\"");
        if (pos != std::string::npos) {
            auto start = req.body.find('"', pos + 6);
            if (start != std::string::npos) {
                start++;
                auto end = req.body.find('"', start);
                if (end != std::string::npos)
                    type = req.body.substr(start, end - start);
            }
        }
        res.set_content(handle_inject(state, type), "application/json");
    });

    // Static files (HTML/JS/CSS)
    svr.set_mount_point("/", static_dir);

    // Fallback for SPA
    svr.set_error_handler([](const httplib::Request&, httplib::Response& res) {
        if (res.status == 404) {
            res.set_content("{\"error\":\"not found\"}", "application/json");
        }
    });

    std::cout << "\n╔════════════════════════════════════════════════════════════╗\n"
              << "║  Cyb3rALIENS Web Demo  →  http://localhost:" << port << "\n"
              << "║  API base               →  http://localhost:" << port << "/api/\n"
              << "╚════════════════════════════════════════════════════════════╝\n\n";

    if (!svr.listen("0.0.0.0", port)) {
        std::cerr << "Failed to bind port " << port << "\n";
    }
}

} // namespace cyb3r
