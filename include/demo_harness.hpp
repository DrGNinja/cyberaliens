#pragma once
#include "common.hpp"
#include "dual_mc.hpp"
#include "p2pe_channel.hpp"
#include "iam_registry.hpp"
#include "bce_ledger.hpp"

namespace cyb3r {

class DemoHarness {
public:
    DemoHarness();

    int run_interactive();
    int run_full_demo();

    void scenario_device_onboarding();
    void scenario_p2pe_communication();
    void scenario_revocation();
    void scenario_list_devices();
    void scenario_show_ledger();
    void scenario_save();
    void scenario_load();
    void scenario_reset();

private:
    IAMRegistry iam_;
    BCELedger   ledger_;

    static constexpr const char* IAM_FILE    = "data/iam_registry.txt";
    static constexpr const char* LEDGER_FILE = "data/bce_ledger.txt";

    void print_menu() const;
};

} // namespace cyb3r
