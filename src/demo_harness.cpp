#include "demo_harness.hpp"
#include <thread>
#include <chrono>
#include <limits>

namespace cyb3r {

DemoHarness::DemoHarness() {
    // Attempt to load previous state if present
    iam_.load(IAM_FILE);
    ledger_.load(LEDGER_FILE);
}

void DemoHarness::print_menu() const {
    std::cout << R"(
┌────────────────────────────────────────────────────────────┐
│  Cyb3rALIENS Pure Simulation – Interactive Menu            │
├────────────────────────────────────────────────────────────┤
│  1. Device Onboarding (Dual-MC → DNA → IAM → BCE)          │
│  2. Point-to-Point Encrypted Communication (P2PE)          │
│  3. Device Revocation                                      │
│  4. List registered devices (IAM)                          │
│  5. Show recent ledger entries (BCE)                       │
│  6. Save state to disk                                     │
│  7. Load state from disk                                   │
│  8. Reset IAM + Ledger                                     │
│  9. Run FULL demo (all scenarios)                          │
│  0. Exit                                                   │
└────────────────────────────────────────────────────────────┘
Choice: )";
}

void DemoHarness::scenario_device_onboarding() {
    LOG_STEP("Scenario – Device Onboarding (Dual-MC → DNA → IAM → BCE)");

    DualMCPair device1(0xA11CE001ULL, 0xA11CE002ULL);
    DualMCPair device2(0xB22DF001ULL, 0xB22DF002ULL);

    device1.perform_handshake();
    device2.perform_handshake();

    const auto& dna1 = device1.master.dna();
    const auto& dna2 = device2.master.dna();

    if (iam_.register_device(dna1, "Alpha prototype device #1"))
        LOG_OK("Registered " + dna1.short_id);
    else
        LOG_INFO(dna1.short_id + " already present");

    if (iam_.register_device(dna2, "Alpha prototype device #2"))
        LOG_OK("Registered " + dna2.short_id);
    else
        LOG_INFO(dna2.short_id + " already present");

    iam_.mark_active(dna1);
    iam_.mark_active(dna2);

    ledger_.append("REGISTER", dna1, nullptr, "onboarding");
    ledger_.append("REGISTER", dna2, nullptr, "onboarding");

    LOG_OK("IAM now holds " + std::to_string(iam_.count()) + " registered devices");
    ledger_.print_recent(5);
}

void DemoHarness::scenario_p2pe_communication() {
    LOG_STEP("Scenario – Point-to-Point Encrypted Communication");

    DualMCPair pair(0xC33E0001ULL, 0xC33E0002ULL);
    pair.perform_handshake();

    const auto& dna_a = pair.master.dna();
    const auto& dna_b = pair.slave.dna();

    iam_.register_device(dna_a, "Comm endpoint A");
    iam_.register_device(dna_b, "Comm endpoint B");
    iam_.mark_active(dna_a);
    iam_.mark_active(dna_b);

    if (!iam_.authorize_pair(dna_a, dna_b)) {
        LOG_WARN("IAM refused authorization – aborting channel");
        return;
    }

    P2PEChannel ch_ab(dna_a, dna_b, pair.validation_key);
    P2PEChannel ch_ba(dna_b, dna_a, pair.validation_key);

    ledger_.append("CHANNEL_OPEN", dna_a, &dna_b, "P2PE established");

    std::string msg1 = "Hello from Device-A – entropy DNA verified";
    std::string msg2 = "Device-B acknowledges secure channel";

    auto ct1 = ch_ab.send(std::vector<uint8_t>(msg1.begin(), msg1.end()));
    auto pt1 = ch_ba.receive(ct1);
    std::string recovered1(pt1.begin(), pt1.end());

    auto ct2 = ch_ba.send(std::vector<uint8_t>(msg2.begin(), msg2.end()));
    auto pt2 = ch_ab.receive(ct2);
    std::string recovered2(pt2.begin(), pt2.end());

    LOG_OK("Message A→B recovered: \"" + recovered1 + "\"");
    LOG_OK("Message B→A recovered: \"" + recovered2 + "\"");

    if (recovered1 == msg1 && recovered2 == msg2)
        LOG_OK("End-to-end P2PE integrity verified");
    else
        LOG_WARN("Message mismatch – check AES implementation");

    ledger_.append("MSG", dna_a, &dna_b, msg1);
    ledger_.append("MSG", dna_b, &dna_a, msg2);
}

void DemoHarness::scenario_revocation() {
    LOG_STEP("Scenario – Device Revocation & Ledger Integrity");

    auto all = iam_.list_all();
    if (all.empty()) {
        LOG_WARN("No devices to revoke – run onboarding first");
        return;
    }

    const auto& target = all.front().dna;
    iam_.revoke(target);
    ledger_.append("REVOKE", target, nullptr, "administrative revocation");

    LOG_OK("Revoked " + target.short_id);
    LOG_INFO("Ledger integrity check: " +
             std::string(ledger_.verify_integrity() ? "PASSED" : "FAILED"));
    ledger_.print_recent(8);
}

void DemoHarness::scenario_list_devices() {
    LOG_STEP("IAM – Registered Devices");
    auto all = iam_.list_all();
    if (all.empty()) {
        LOG_INFO("No devices registered yet");
        return;
    }
    for (const auto& r : all) {
        std::cout << "  " << r.dna.short_id
                  << "  status=" << r.status
                  << "  notes=\"" << r.notes << "\"\n";
    }
    LOG_OK(std::to_string(all.size()) + " device(s)");
}

void DemoHarness::scenario_show_ledger() {
    LOG_STEP("BCE Ledger – Recent Entries");
    ledger_.print_recent(15);
    LOG_INFO("Integrity: " + std::string(ledger_.verify_integrity() ? "OK" : "BROKEN"));
}

void DemoHarness::scenario_save() {
    bool ok1 = iam_.save(IAM_FILE);
    bool ok2 = ledger_.save(LEDGER_FILE);
    if (ok1 && ok2)
        LOG_OK("State saved to data/iam_registry.txt and data/bce_ledger.txt");
    else
        LOG_WARN("Save failed – check data/ directory permissions");
}

void DemoHarness::scenario_load() {
    bool ok1 = iam_.load(IAM_FILE);
    bool ok2 = ledger_.load(LEDGER_FILE);
    if (ok1 || ok2)
        LOG_OK("State loaded (IAM devices=" + std::to_string(iam_.count()) +
               ", ledger entries=" + std::to_string(ledger_.size()) + ")");
    else
        LOG_WARN("Nothing to load or files missing");
}

void DemoHarness::scenario_reset() {
    iam_.clear();
    ledger_.reset();
    LOG_OK("IAM and Ledger reset to empty/genesis state");
}

int DemoHarness::run_full_demo() {
    std::cout << R"(
╔══════════════════════════════════════════════════════════════╗
║          Cyb3rALIENS  –  Pure Software Simulation            ║
║   Dual-MCU  ·  Digital DNA  ·  AES-SEA  ·  P2PE  ·  IAM/BCE  ║
║              (Patent US10673617B1 inspired)                  ║
╚══════════════════════════════════════════════════════════════╝
)" << "\n";

    try {
        scenario_device_onboarding();
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
        scenario_p2pe_communication();
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
        scenario_revocation();
        scenario_save();
        LOG_STEP("Full demo complete");
        return 0;
    }
    catch (const std::exception& ex) {
        LOG_WARN(std::string("Fatal: ") + ex.what());
        return 1;
    }
}

int DemoHarness::run_interactive() {
    std::cout << R"(
╔══════════════════════════════════════════════════════════════╗
║          Cyb3rALIENS  –  Pure Software Simulation            ║
║              Interactive Mode                                ║
╚══════════════════════════════════════════════════════════════╝
)" << "\n";

    // Load any previous state
    scenario_load();

    while (true) {
        print_menu();
        int choice = -1;
        if (!(std::cin >> choice)) {
            std::cin.clear();
            std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
            continue;
        }
        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');

        try {
            switch (choice) {
                case 1: scenario_device_onboarding(); break;
                case 2: scenario_p2pe_communication(); break;
                case 3: scenario_revocation(); break;
                case 4: scenario_list_devices(); break;
                case 5: scenario_show_ledger(); break;
                case 6: scenario_save(); break;
                case 7: scenario_load(); break;
                case 8: scenario_reset(); break;
                case 9: run_full_demo(); break;
                case 0:
                    scenario_save();
                    LOG_OK("Goodbye");
                    return 0;
                default:
                    LOG_WARN("Invalid choice");
            }
        }
        catch (const std::exception& ex) {
            LOG_WARN(std::string("Error: ") + ex.what());
        }
    }
}

} // namespace cyb3r
