#include "demo_harness.hpp"
#include "web_api.hpp"
#include <cstring>
#include <string>

int main(int argc, char* argv[]) {
    // Web server mode
    if (argc > 1 && (std::strcmp(argv[1], "--web") == 0 || std::strcmp(argv[1], "-w") == 0)) {
        int port = 8080;
        if (argc > 2) port = std::atoi(argv[2]);
        cyb3r::SimState state;
        // Try to load previous state
        state.iam.load("data/iam_registry.txt");
        state.ledger.load("data/bce_ledger.txt");
        cyb3r::run_web_server(state, "web", port);
        return 0;
    }

    cyb3r::DemoHarness harness;

    // Non-interactive full demo
    if (argc > 1 && (std::strcmp(argv[1], "--demo") == 0 || std::strcmp(argv[1], "-d") == 0)) {
        return harness.run_full_demo();
    }

    // Default: interactive console menu
    return harness.run_interactive();
}
